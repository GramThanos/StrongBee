#!/usr/bin/python3
# Test StrongBee Server using StrongMonkey

import sys
import json
import base64
import hashlib
import binascii
import cryptography

# https://github.com/Yubico/python-fido2/
# sudo python3.8 -m pip install fido2
import fido2
import fido2.client
import fido2.server
import fido2.ctap2
import fido2.cbor

# https://github.com/bodik/soft-webauthn
# sudo python3.8 -m pip install soft-webauthn
import soft_webauthn

# Include Library
import StrongMonkey

# Don't validate SSL certificate
StrongMonkey.STRONGMONKEY_DEBUG = True

# Print library info
print("Using StrongMonkey " + StrongMonkey.STRONGMONKEY_VESION);

# StrongKey FIDO info
FS_URL = 'https://localhost:8181'
FS_DID = 2
FS_DID = 'unipi.gr'
FS_PROTOCOL = 'REST' # Only REST is currently supported
# Authentication using HMAC
FS_AUTH = 'HMAC'
FS_KEYID = 'b55938050b05019a'
FS_KEYSECRET = '40e5b172b3d01c204f5e301d132e4fa6'
# or Authentication using Password
#FS_AUTH = 'PASSWORD'
#FS_KEYID = 'svcfidouser'
#FS_KEYSECRET = 'Abcd1234!'

# Set the missing Relay Party ID
RPID = "unipi.gr"
ORIGIN = "https://" + RPID
USERHANDLE = "gramthanos@gmail.com"


# Initialize
monkey = StrongMonkey.StrongMonkey(FS_URL, FS_DID, FS_PROTOCOL, FS_AUTH, FS_KEYID, FS_KEYSECRET)


# --------------------------------------------------------------------------------
# Create a ping request
print("-----------------------------------")
print("Ping request ... ", end='')
result = monkey.ping()
error = monkey.getError(result)
if (error):
	print("failed")
	print("\t" + error)
	sys.exit(0)
print("ok")
# Print server info
print(result)

# --------------------------------------------------------------------------------
# Create a preregister request
print("-----------------------------------")
print("Pre-register request ... ", end='')
result = monkey.preregister(USERHANDLE)
error = monkey.getError(result)
if error:
    print("failed")
    print("\t" + error)
    sys.exit(0)
print("ok")
print(json.dumps(result))
print("")

result["Response"]["rp"]["id"] = RPID
result["Response"]["rp"]["name"] = 'Testing'

# Create Authenticator Device
print("Creating authenticator attestation ... ", end='')
authenticator = soft_webauthn.SoftWebauthnDevice()
options = {'publicKey' : result["Response"]}
options['publicKey']['challenge'] = base64.urlsafe_b64decode(options['publicKey']['challenge'] + ('=' * (-len(options['publicKey']['challenge']) % 4)))
attestation = authenticator.create(options, ORIGIN)
attestation['id'] = attestation['id'].decode('ascii').rstrip('=')
attestation['rawId'] = base64.urlsafe_b64encode(attestation['rawId']).decode('ascii').rstrip('=')
attestation['response']['clientDataJSON'] = base64.urlsafe_b64encode(attestation['response']['clientDataJSON']).decode('ascii').rstrip('=')
attestation['response']['attestationObject'] = base64.urlsafe_b64encode(attestation['response']['attestationObject']).decode('ascii').rstrip('=')
print("ok")
print(json.dumps(attestation))

# Create a register request
print("Register request ... ", end='')
result = monkey.register(attestation, {
	'version' : '1.0',
	'create_location' : 'testing',
	'username' : USERHANDLE,
	'origin' : ORIGIN
})
error = monkey.getError(result)
if error:
	print("failed")
	print("\t" + error)
	sys.exit(0)
print("ok")
print(json.dumps(result))
print("")

# --------------------------------------------------------------------------------
# Create a preauthenticate request
print("-----------------------------------")
print("Pre-authenticate request ... ", end='')
result = monkey.preauthenticate(USERHANDLE)
error = monkey.getError(result)
if (error):
	print("failed")
	print("\t" + error)
	sys.exit(0)
print("ok")
print(json.dumps(result))
result["Response"]["rpId"] = RPID

# Get from Authenticator Device
print("Getting authenticator assertion ... ", end='')
options = {'publicKey' : result["Response"]}
options['publicKey']['challenge'] = base64.urlsafe_b64decode(options['publicKey']['challenge'] + ('=' * (-len(options['publicKey']['challenge']) % 4)))
assertion = authenticator.get(options, ORIGIN)
assertion['id'] = assertion['id'].decode('ascii').rstrip('=')
assertion['rawId'] = base64.urlsafe_b64encode(assertion['rawId']).decode('ascii').rstrip('=')
assertion['response']['authenticatorData'] = base64.urlsafe_b64encode(assertion['response']['authenticatorData']).decode('ascii').rstrip('=')
assertion['response']['clientDataJSON'] = base64.urlsafe_b64encode(assertion['response']['clientDataJSON']).decode('ascii').rstrip('=')
assertion['response']['signature'] = base64.urlsafe_b64encode(assertion['response']['signature']).decode('ascii').rstrip('=')
print("ok")
print(assertion)
print("")


# Create an authenticate request
print("-----------------------------------")
print("Authenticate request ... ", end='')
result = monkey.authenticate(assertion, {
	'version' : '1.0',
	'last_used_location' : 'testing',
	'username' : USERHANDLE,
	'origin' : ORIGIN
})
error = monkey.getError(result)
if (error):
	print("failed")
	print("\t" + error)
	sys.exit(0)
print("ok")
print(json.dumps(result))
print("")

# --------------------------------------------------------------------------------
# Create a getkeysinfo request
print("-----------------------------------")
print("Get keys info request ... ", end='')
result = monkey.getkeysinfo(USERHANDLE)
error = monkey.getError(result)
if (error):
	print("failed")
	print("\t" + error)
	sys.exit(0)
print("ok")
print(json.dumps(result))

# Get a testing keys
keys = []
for key in result['Response']['keys']:
	if key['createLocation'] == 'testing':
		keys.append(key['randomid'])
if len(keys) > 0:
	print("Found " + str(len(keys)) + " keys on the list.")
else:
	print("No testing key found on the list.")
	sys.exit(0)
print("")

# --------------------------------------------------------------------------------
# Delete generated key
print("-----------------------------------")
for keyid in keys:
	print("De-register key %s ... " % (keyid,), end='')
	result = monkey.deregister(keyid)
	error = monkey.getError(result)
	if (error):
		print("failed")
		print("\t" + error)
		sys.exit(0)
	print("ok")
	print(json.dumps(result))
print("")


# --------------------------------------------------------------------------------
print("-----------------------------------")
print("All tests were executed successfully!")
