# 
# StrongBee v0.0.3-beta
# 
# Copyright (c) 2021 Grammatopoulos Athanasios-Vasileios
# in collaboration with  Systems Security Laboratory at
# Department of Digital Systems at University of Piraeus
#

import re, json, functools, hashlib, base64
from flask import abort, request, g
from strongbee.utilities import rAbort
from strongbee.models import Domains, APIUser, APICredentials


def verifyUserAuthentication(data):
	"""
	Verify the authentication of the user (username and password)

	:param data: the data send on the request
	:return: True/False
	"""
	# Check given data
	if data and data['svcinfo'] and ('svcusername' in data['svcinfo'].keys()) and ('svcpassword' in data['svcinfo'].keys()):
		# Validate API user provided credentials
		if APIUser.authenticate(data['svcinfo']['svcusername'], data['svcinfo']['svcpassword']):
			# Successful authentication
			return True
	# Authentication failed
	return False


def verifyCredentialsAuthentication(data, headers, method, path, payload):
	"""
	Verify the authentication of the credentials (keyid and signature)

	:param data: the data send on the request
	:param headers: the headers send on the request
	:param path: the path send on the request
	:param payload: the payload send on the request data
	:return: True/False
	"""

	# Parse header to lowercase keys
	headers = {k.lower(): v for k, v in headers.items()}
	headers_keys = headers.keys()

	# Check if authorization and date headers are given
	if 'date' in headers_keys:
		datestr = headers['date']
	else:
		# Authentication failed - missing date header
		return False

	# Retrieve content hash
	if 'strongbee-content-sha256' in headers_keys:
		content_hash = headers['strongbee-content-sha256']
	elif 'strongkey-content-sha256' in headers_keys:
		content_hash = headers['strongkey-content-sha256'] # for compatibility
	else:
		# Authentication failed - missing content sha256 header
		return False

	# Retrieve API version
	if 'strongbee-api-version' in headers_keys:
		api_version = headers['strongbee-api-version']
	elif 'strongkey-api-version' in headers_keys:
		api_version = headers['strongkey-api-version'] # for compatibility
	else:
		# Authentication failed - missing API version header
		return False

	# Retrieve keyid and hmachash
	if 'authorization' in headers_keys:
		auth = re.match(r'^HMAC (?P<keyid>[a-zA-Z0-9]+?):(?P<hmachash>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$', headers['authorization'])
		if auth:
			keyid = auth.groupdict()['keyid']
			hmachash = auth.groupdict()['hmachash']
		else:
			# Authentication failed - invalid authorization header format
			return False
	else:
		# Authentication failed - missing authorization header
		return False
	
	# Prepare payload hash and mime-type
	payload_hash = ''
	mimetype = ''
	if not (payload is None):
		payload_string = json.dumps(payload, separators=(',', ':'))
		payload_hash = hashlib.sha256(payload_string.encode()).digest()
		payload_hash = base64.b64encode(payload_hash).decode()
		mimetype = headers['content-type'] if 'content-type' in headers_keys else ''

	# Generate message
	message = [method, payload_hash, mimetype, datestr, api_version, path]
	message = "\n".join(message)

	# Validate correct signature
	if APICredentials.authenticate(keyid, hmachash, message):
		# Authentication successful
		return True

	# Authentication failed - invalid signature
	return False


def isAuthenticated():
	"""
	Validate that the request is authenticated
	"""
	def decorator(func):
		@functools.wraps(func)
		def authenticate(*args, **kwargs):
			# Get data from request
			data = request.get_json(force=True, silent=True)

			# Check svcinfo information
			if not data or not 'svcinfo' in data.keys() or not 'authtype' in data['svcinfo'].keys():
				return rAbort('AUTH_FAILED')
			if not ('protocol' in data['svcinfo'].keys() and data['svcinfo']['protocol'] == 'FIDO2_0'):
				return rAbort('AUTH_FAILED')
			
			# Check did
			if not 'did' in data['svcinfo'].keys():
				return rAbort('AUTH_FAILED')
			# Parse did
			domain = None
			did = data['svcinfo']['did']
			if isinstance(did, str):
				domain = Domains.getByName(did)
			elif isinstance(did, int):
				domain = Domains.getById(did)
			if not domain:
				return rAbort('AUTH_FAILED')

			# Parse payload (if any)
			payload = data['payload'] if data and 'payload' in data.keys() else None

			# If authentication type PASSWORD
			if data['svcinfo']['authtype'] == 'PASSWORD':
				if not verifyUserAuthentication(data):
					return rAbort('AUTH_FAILED')
			# If authentication type HMAC
			elif data['svcinfo']['authtype'] == 'HMAC':
				if not verifyCredentialsAuthentication(data, request.headers, request.method, request.path, payload):
					return rAbort('AUTH_FAILED')
			# Else error
			else:
				return rAbort('AUTH_FAILED')

			# TODO: Should we check if API User/Credentials have access to the domain?

			# Save request info
			g.domain = domain
			g.payload = payload

			return func(*args, **kwargs)
		return authenticate
	return decorator
