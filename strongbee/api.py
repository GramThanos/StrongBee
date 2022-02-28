# 
# StrongBee v0.0.3-beta
# 
# Copyright (c) 2021 Grammatopoulos Athanasios-Vasileios
# in collaboration with  Systems Security Laboratory at
# Department of Digital Systems at University of Piraeus
#

#
# The Server's API is based on
# 	FIDO2 Server API - 3.0.0 - OAS3
# 	https://strongkey.github.io/fido2/
# 	

import datetime, json
from flask import request, Blueprint, current_app, g
from strongbee.models import PublicKeys, States
from strongbee.utilities import rMessage, rRawMessage, rError, base64Decode, base64Encode
from strongbee.authen import isAuthenticated
# FIDO2 Library
from fido2 import ctap2 as Fido2CTAP, server as Fido2Server, client as Fido2Client

# Generate Blueprint for the API
api = Blueprint('api', __name__)


@api.route('/ping', methods=['POST'])
@isAuthenticated()
def ping():
	"""
	Handle /ping requests

	:return: Raw message with the server's information
	"""
	# Gather information
	did = str(g.domain.did)
	server_name = current_app.config['INFO']['NAME']
	server_description = current_app.config['INFO']['DESCRIPTION']
	server_host = request.host
	current_datetime = datetime.datetime.utcnow().strftime('%a %b %d %H:%M:%S UTC %Y')
	server_started_datetime = current_app.server_start_date.strftime('%a %b %d %H:%M:%S UTC %Y')
	# Return info
	return rRawMessage(
		server_name + ', ' + server_description + '\n' +
		'Hostname: ' + server_host + '\n' +
		'Current time: ' + current_datetime + '\n' +
		'Up since: ' + server_started_datetime + '\n' +
		'FIDO Server Domain ' + did + ' is alive!\n'
	)


#
# Registration - preregister
#
@api.route('/preregister', methods=['POST'])
@isAuthenticated()
def preregister():
	# If no payload throw error
	if not (
		g.payload and
		'username' in g.payload.keys() and isinstance(g.payload['username'], str) and
		'displayname' in g.payload.keys() and isinstance(g.payload['displayname'], str)
	):
		return rError('INPUT_ERROR', 'Invalid payload, missing usernam or displayname')

	# Get already saved keys
	excludekeys = []
	publickeys = PublicKeys.getByUsername(g.payload['username'])
	try:
		for key in publickeys:
			excludekeys.append(Fido2CTAP.AttestedCredentialData(base64Decode(key.keydata.encode())))
	except ValueError as e:
		return rError('INPUT_ERROR', e)

	# ToDo: Handle options & extensions
	#if 'options' in g.payload.keys() and isinstance(g.payload['options'], str):
	#	pass
	#if 'extensions' in g.payload.keys() and isinstance(g.payload['displayname'], str):
	#	pass

	# Prepare challenge
	try:
		server = Fido2Server.Fido2Server({'id': g.domain.name, 'name': g.domain.name})
		options, state = server.register_begin({
			'id': g.payload['username'].encode(),
			'name': g.payload['displayname']
		}, credentials=excludekeys)
	except ValueError as e:
		return rError('INPUT_ERROR', e)

	# Parse bytes values
	options['publicKey']['user']['id'] = base64Encode(options['publicKey']['user']['id']).decode()
	options['publicKey']['challenge'] = base64Encode(options['publicKey']['challenge']).decode()
	options['publicKey']['user']['displayName'] = options['publicKey']['user']['name']
	for key in options['publicKey']['excludeCredentials']:
		key['id'] = base64Encode(key['id']).decode()

	options['publicKey']['timeout'] = 60000

	# Save state
	expiration = datetime.datetime.now() + datetime.timedelta(milliseconds=(options['publicKey']['timeout'] + 1000))
	States.create('registration', options['publicKey']['challenge'], g.payload['username'], expiration, state)

	# Return response
	return rMessage(options['publicKey'])


#
# Registration - register
#
@api.route('/register', methods=['POST'])
@isAuthenticated()
def register():
	# If no payload throw error
	if not (
		g.payload and
		'metadata' in g.payload.keys() and isinstance(g.payload['metadata'], str) and
		'response' in g.payload.keys() and isinstance(g.payload['response'], str)
	):
		return rError('INPUT_ERROR', 'Invalid payload, missing metadata or response')

	# Parse metadata
	metadata = json.loads(g.payload['metadata'])
	if not metadata or not ('create_location' in metadata.keys() and 'username' in metadata.keys() and 'origin' in metadata.keys()):
		return rError('INPUT_ERROR', 'Invalid metadata, missing create_location or username or origin')

	# Parse response
	response = json.loads(g.payload['response'])
	clientDataBytes = base64Decode(response['response']['clientDataJSON'].encode())
	attestationBytes = base64Decode(response['response']['attestationObject'].encode())
	
	# Retrieve challenge & state
	clientData = json.loads(clientDataBytes.decode())
	state = States.get('registration', clientData['challenge'])
	if not state or not state.challenge == clientData['challenge']: # Checking challenge here is probably not needed
		return rError('INPUT_ERROR', 'Invalid state (state not found)')
	States.deleteAndClean('registration', clientData['challenge'])

	# Complete registration
	try:
		server = Fido2Server.Fido2Server({'id': g.domain.name, 'name': g.domain.name})
		auth_data = server.register_complete(state.getState(), Fido2Client.ClientData(clientDataBytes), Fido2CTAP.AttestationObject(attestationBytes))
	except ValueError as e:
		return rError('INPUT_ERROR', e)

	# Save key data
	info = {
		'keyid' : base64Encode(auth_data.credential_data.credential_id).decode(),
		'username' : state.username,
		'displayname' : state.username,
		'keydata' : base64Encode(auth_data.credential_data).decode(),
		'create_location' : metadata['create_location'],
		'metadata_origin' : metadata['origin']
	}
	PublicKeys.create(info['keyid'], info['username'], info['displayname'], info['keydata'], info['create_location'], info['metadata_origin'])

	# Return response
	return rMessage('Successfully processed registration response')


#
# Authentication - preauthenticate
#
@api.route('/preauthenticate', methods=['POST'])
@isAuthenticated()
def preauthenticate():
	# If no payload throw error
	if not (
		g.payload and
		'username' in g.payload.keys() and isinstance(g.payload['username'], str)
	):
		return rError('INPUT_ERROR', 'Invalid username in payload')

	# Get already saved keys
	credentials = []
	publickeys = PublicKeys.getByUsername(g.payload['username'])
	try:
		for key in publickeys:
			credentials.append(Fido2CTAP.AttestedCredentialData(base64Decode(key.keydata.encode())))
	except ValueError as e:
		return rError('INPUT_ERROR', e)
	# If user has no credentials
	if len(credentials) < 1:
		return rError('INPUT_ERROR', 'Credentials were not found')

	# TODO: Handle options & extensions
	#if 'options' in g.payload.keys() and isinstance(g.payload['options'], str):
	#	pass

	# Prepare challenge
	try:
		server = Fido2Server.Fido2Server({'id': g.domain.name, 'name': g.domain.name})
		options, state = server.authenticate_begin(credentials)
	except ValueError as e:
		return rError('INPUT_ERROR', e)

	# Parse bytes values
	options['publicKey']['challenge'] = base64Encode(options['publicKey']['challenge']).decode()
	for key in options['publicKey']['allowCredentials']:
		key['id'] = base64Encode(key['id']).decode()

	options['publicKey']['timeout'] = 60000

	# Save state
	expiration = datetime.datetime.now() + datetime.timedelta(milliseconds=(options['publicKey']['timeout'] + 1000))
	States.create('authentication', options['publicKey']['challenge'], g.payload['username'], expiration, state)

	# Return response
	return rMessage(options['publicKey'])


#
# Authentication - authenticate
#
@api.route('/authenticate', methods=['POST'])
@isAuthenticated()
def authenticate():
	# If no payload throw error
	if not (
		g.payload and
		'metadata' in g.payload.keys() and isinstance(g.payload['metadata'], str) and
		'response' in g.payload.keys() and isinstance(g.payload['response'], str)
	):
		return rError('INPUT_ERROR', 'Invalid payload')

	# Parse metadata
	metadata = json.loads(g.payload['metadata'])
	if not metadata or not ('last_used_location' in metadata.keys() and 'username' in metadata.keys() and 'origin' in metadata.keys()):
		return rError('INPUT_ERROR', 'Invalid meta-data')

	# Parse response
	response = json.loads(g.payload['response'])
	if not all(x in response['response'].keys() for x in ['clientDataJSON', 'authenticatorData', 'signature']):
		return rError('INPUT_ERROR', 'Invalid payload response')
	credentialId = base64Decode(response['id'].encode())
	clientDataBytes = base64Decode(response['response']['clientDataJSON'].encode())
	authenticatorDataBytes = base64Decode(response['response']['authenticatorData'].encode())
	signatureBytes = base64Decode(response['response']['signature'].encode())
	userHandleBytes = base64Decode(response['response']['userHandle'].encode()) if 'userHandle' in response['response'].keys() else None
	
	# Retrieve challenge & state
	clientData = json.loads(clientDataBytes.decode())
	state = States.get('authentication', clientData['challenge'])
	if not state or not state.challenge == clientData['challenge']:
		return rError('INPUT_ERROR', 'Given challenge do not match with the saved state')
	States.deleteAndClean('authentication', clientData['challenge'])

	# Get already saved keys
	credentials = []
	publickeys = PublicKeys.getByUsername(state.username)
	try:
		for key in publickeys:
			credentials.append(Fido2CTAP.AttestedCredentialData(base64Decode(key.keydata.encode())))
	except ValueError as e:
		return rError('INPUT_ERROR', e)
	# If user has no credentials
	if len(credentials) < 1:
		return rError('INPUT_ERROR', 'Credentials were not found')

	# Complete registration
	try:
		server = Fido2Server.Fido2Server({'id': g.domain.name, 'name': g.domain.name})
		auth_data = server.authenticate_complete(state.getState(), credentials, credentialId, Fido2Client.ClientData(clientDataBytes), Fido2CTAP.AuthenticatorData(authenticatorDataBytes), signatureBytes)
	except ValueError as e:
		#raise e
		return rError('INPUT_ERROR', e)

	# Return response
	return rMessage('Successfully authenticated key')


#
# Key Regulation - updatekeyinfo
#
@api.route('/updatekeyinfo', methods=['POST'])
@isAuthenticated()
def updatekeyinfo():
	# If no payload throw error
	if not (
		g.payload and
		'keyid' in g.payload.keys() and isinstance(g.payload['keyid'], str) and
		'status' in g.payload.keys() and isinstance(g.payload['status'], str) and
		'modify_location' in g.payload.keys() and isinstance(g.payload['modify_location'], str) and
		'displayname' in g.payload.keys() and isinstance(g.payload['displayname'], str)
	):
		return rError('INPUT_ERROR', 'Invalid payload (keyid, status, modify_location, displayname)')

	# Get key
	key = PublicKeys.getById(g.payload['keyid'])
	if not key:
		return rError('INPUT_ERROR', 'Key was not found')

	# Update info
	key = PublicKeys.updateById(key.keyid, g.payload['status'], g.payload['modify_location'], g.payload['displayname'])
	
	# Return key info
	return rMessage({
		'randomid' : key.keyid,
		'randomid_ttl_seconds' : '9999',
		'fidoProtocol' : 'FIDO2_0',
		'fidoVersion' : 'FIDO2_0',
		'createLocation' : key.create_location,
		'createDate' : key.create_date,
		'lastusedLocation' : key.last_used_location,
		'modifyDate' : key.modify_date,
		'status' : key.status,
		'displayName' : key.displayname
	})


#
# Key Regulation - getkeysinfo
#
@api.route('/getkeysinfo', methods=['POST'])
@isAuthenticated()
def getkeysinfo():
	# If no payload throw error
	if not (
		g.payload and
		'username' in g.payload.keys() and isinstance(g.payload['username'], str)
	):
		return rError('INPUT_ERROR', 'Invalid username in payload')

	publickeys = PublicKeys.getByUsername(g.payload['username'])
	keys = []
	for key in publickeys:
		keys.append({
			'randomid' : key.keyid,
			'randomid_ttl_seconds' : '9999',
			'fidoProtocol' : 'FIDO2_0',
			'fidoVersion' : 'FIDO2_0',
			'createLocation' : key.create_location,
			'createDate' : key.create_date,
			'lastusedLocation' : key.last_used_location,
			'modifyDate' : key.modify_date,
			'status' : key.status,
			'displayName' : key.displayname
		})
	return rMessage({'keys' : keys})


#
# Key Regulation - deregister
#
@api.route('/deregister', methods=['POST'])
@isAuthenticated()
def deregister():
	# If no payload throw error
	if not (
		g.payload and
		'keyid' in g.payload.keys() and isinstance(g.payload['keyid'], str)
	):
		return rError('INPUT_ERROR', 'Invalid keyid in payload')

	# Get key
	publickey = PublicKeys.getById(g.payload['keyid'])
	if not publickey:
		return rError('INPUT_ERROR', 'Key was not found')

	# Remove key
	PublicKeys.deleteById(publickey.keyid)
	
	# Return key info
	key = publickey
	return rMessage({
		'randomid' : key.keyid,
		'randomid_ttl_seconds' : '9999',
		'fidoProtocol' : 'FIDO2_0',
		'fidoVersion' : 'FIDO2_0',
		'createLocation' : key.create_location,
		'createDate' : key.create_date,
		'lastusedLocation' : key.last_used_location,
		'modifyDate' : key.modify_date,
		'status' : key.status,
		'displayName' : key.displayname
	})
