# 
# StrongBee v0.0.3-beta
# 
# Copyright (c) 2021 Grammatopoulos Athanasios-Vasileios
# in collaboration with  Systems Security Laboratory at
# Department of Digital Systems at University of Piraeus
#

import base64, functools, json
from flask import abort, request

# Server Response Codes and Messages
TYPE = {
	'OK' :                      {'CODE' : 200, 'MESSAGE': "Successful request"},
	'INPUT_ERROR' :             {'CODE' : 400, 'MESSAGE': "There was an error in the submitted input."},
	'AUTH_FAILED' :             {'CODE' : 401, 'MESSAGE': "The HMAC authentication failed."},
	'REQUEST_UNAVAILABLE' :     {'CODE' : 404, 'MESSAGE': "The requested resource is unavailable."},
	'SERVER_EXCEPTION' :        {'CODE' : 500, 'MESSAGE': "Internal server error."},
	'UNUSED_ROUTES_EXCEPTION' : {'CODE' : 501, 'MESSAGE': "Internal server error."}
}


def rError(etype, info=None):
	"""
	Create an error response based on the given type

	:param etype: the type of error to be returned
	:param info: debugging information about the error
	:return: JSON string
	"""
	if info != None and  current_app.config['VERBOSE_ERRORS']:
		# Print info
		print(info)
		# If it is error, print stack
		if isinstance(info, Exception):
			print(info.__traceback__ )
	# Return error
	return json.dumps({"Error": TYPE[etype]['MESSAGE']}), TYPE[etype]['CODE']


def rAbort(etype):
	"""
	Abort the process of the request responding using the given error type

	:param etype: the type of error to be returned
	"""
	return abort(TYPE[etype]['CODE'], json.dumps({"Error": TYPE[etype]['MESSAGE']}))


def rMessage(message):
	"""
	Create an OK JSON response using the given message

	:param message: the response message to return
	:return: JSON string, HTTP Code
	"""
	return json.dumps({"Response": message}), TYPE['OK']['CODE']


def rRawMessage(message):
	"""
	Create an OK RAW response using the given message

	:param message: the response message to return
	:return: JSON string, HTTP Code
	"""
	return message, TYPE['OK']['CODE']


def base64Encode(b):
	"""
	Encode the given bytes to Base64

	:param b: the bytes to encode
	:return: Base64 encoded string
	"""
	return base64.urlsafe_b64encode(b).decode().rstrip('=').encode()


def base64Decode(b):
	"""
	Decode the given bytes from Base64

	:param b: the bytes to decode
	:return: bytes decoded from Base64
	"""
	return base64.urlsafe_b64decode((b.decode() + ('=' * (4 - (len(b) % 4)))).encode())
