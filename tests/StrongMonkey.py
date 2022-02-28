#!/usr/bin/python3
#
# StrongMonkey v0.0.4-beta
# Python SDK for interacting with FIDO2 Server API v3.0.0
# Copyright (c) 2020 Grammatopoulos Athanasios-Vasileios
#

import os
import json
import base64
import hmac
import hashlib
import datetime
import requests
import sys

STRONGMONKEY_VESION = 'v0.0.4-beta';
STRONGMONKEY_DEBUG = False;
STRONGMONKEY_CONNECTTIMEOUT = 10;
STRONGMONKEY_TIMEOUT = 30;
STRONGMONKEY_USERAGENT = 'StrongMonkey-Agent' + '/' + STRONGMONKEY_VESION;

class StrongMonkey:

    # Static variables
    api_protocol = 'FIDO2_0';
    api_version = 'SK3_0';
    api_url_base = '/skfs/rest';
    version = STRONGMONKEY_VESION;
    useragent = STRONGMONKEY_USERAGENT;

    # ERRORS
    PARSE_ERROR = 1001;
    SUBMIT_ERROR = 1002;
    AUTHENTICATION_FAILED = 1003;
    RESOURCE_UNAVAILABLE = 1004;
    UNEXPECTED_ERROR = 1005;
    UNUSED_ROUTES = 1006;
    UNKNOWN_ERROR = 1007;

    # Authorization Methods
    AUTHORIZATION_HMAC = 'HMAC';
    AUTHORIZATION_PASSWORD = 'PASSWORD';
    # Protocol Methods
    PROTOCOL_REST = 'REST';


    def __init__ (self, hostport, did, protocol, authtype, keyid, keysecret):
        # TODO: Test inputs? No?
        # Save information
        self.hostport = hostport
        self.did = did
        self.protocol = protocol
        self.authtype = authtype
        self.keyid = keyid
        self.keysecret = keysecret

        # Check if not supported
        if (authtype != StrongMonkey.AUTHORIZATION_HMAC and authtype != StrongMonkey.AUTHORIZATION_PASSWORD):
            print('The provided authorization method is not supported')
        if (protocol != StrongMonkey.PROTOCOL_REST):
            print('The provided protocol is not supported')

    def preregister (self, username, displayname=None, options=None, extensions=None):
        # Init parameters
        if (displayname is None):
            displayname = username
        options = self.jsonStringPrepare(options, {})
        extensions = self.jsonStringPrepare(extensions, {})

        # Create data
        payload = {
            'username' : username,
            'displayname' : displayname,
            'options' : options,
            'extensions' : extensions
        };

        # Make preregister request
        return self.request(payload, '/preregister');

    def register (self, response, metadata=None):
        # Init empty parameters
        response = self.jsonStringPrepare(response)
        metadata = self.jsonStringPrepare(metadata, {})

        # Create data
        payload = {
            'response' : response,
            'metadata' : metadata
        }

        # Make register request
        return self.request(payload, '/register')

    def preauthenticate (self, username=None, options=None, extensions=None):
        # Init empty parameters
        options = self.jsonStringPrepare(options, {})
        extensions = self.jsonStringPrepare(extensions, {})

        # Create data
        payload = {
            'username' : username,
            'options' : options,
            'extensions' : extensions
        }

        # Make preauthenticate request
        return self.request(payload, '/preauthenticate')

    def authenticate (self, response, metadata=None):
        # Init empty parameters
        response = self.jsonStringPrepare(response)
        metadata = self.jsonStringPrepare(metadata, {})

        # Create data
        payload = {
            'response' : response,
            'metadata' : metadata
        }

        # Make authenticate request
        return self.request(payload, '/authenticate')

    def updatekeyinfo (self, status, modify_location, displayname, keyid):
        # Create data
        payload = {
            "status" : status,
            "modify_location" : modify_location,
            "displayname" : displayname,
            "keyid" : keyid
        }

        # Make updatekeyinfo request
        return self.request(payload, '/updatekeyinfo')

    def getkeysinfo (self, username):
        # Create data
        payload = {
            "username" : username
        }

        # Make getkeysinfo request
        return self.request(payload, '/getkeysinfo')

    def deregister (self, keyid):
        # Create data
        payload = {
            "keyid" : keyid
        }

        # Make deregister request
        return self.request(payload, '/deregister')

    def ping (self):
        # Make ping request
        response = self.request(None, '/ping', False)
        # If no error
        if (response['code'] == 200):
            return response['body']

        # Return error code
        return self.parseResponse(response['code'], response['body'])

    def request (self, payload, action_path, parse=True):
        global STRONGMONKEY_DEBUG, STRONGMONKEY_CONNECTTIMEOUT, STRONGMONKEY_TIMEOUT
        # Create data
        body = {
            "svcinfo" : {
                "did" : self.did,
                "protocol" : StrongMonkey.api_protocol,
                "authtype" : self.authtype
            }
        }
        # Prepare payload
        if not (payload is None):
            body['payload'] = payload

        # Generate path
        path = StrongMonkey.api_url_base + action_path

        # Prepare Request Headers
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': StrongMonkey.useragent
        }

        # HMAC
        if (self.authtype == StrongMonkey.AUTHORIZATION_HMAC):
            # Get date
            date = datetime.datetime.now(datetime.timezone.utc).strftime("%a, %-d %b %Y %H:%M:%S %Z")

            # Prepare hashes
            payload_hash = ''
            mimetype = ''
            if not (payload is None):
                payload_string = json.dumps(body['payload'],separators=(',', ':'))
                payload_hash = hashlib.sha256(payload_string.encode()).digest()
                payload_hash = base64.b64encode(payload_hash).decode()
                mimetype = 'application/json'
            
            # Generate HMAC authentication
            authentication_hash = self.generateHMAC('POST', payload_hash, mimetype, date, path)
            
            # Add authorization Headers
            headers['strongkey-content-sha256'] = payload_hash
            headers['Date'] = date
            headers['strongkey-api-version'] = StrongMonkey.api_version
            headers['Authorization'] = authentication_hash
        # Credentials
        else:
            body['svcinfo']['svcusername'] = self.keyid
            body['svcinfo']['svcpassword'] = self.keysecret

        # Create request
        reqOptions = {
            'url' : self.hostport + path,
            'verify' : True,
            'data' : json.dumps(body),
            'headers' : headers,
            'timeout' : STRONGMONKEY_TIMEOUT
        }
        if (STRONGMONKEY_DEBUG):
            requests.packages.urllib3.disable_warnings()
            reqOptions['verify'] = False
        ch = requests.post(
            reqOptions['url'],
            verify = reqOptions['verify'],
            data = reqOptions['data'],
            headers = reqOptions['headers'],
            timeout = reqOptions['timeout']
        )
        response = ch.text
        response_code = ch.status_code

        if (parse):
            return self.parseResponse(response_code, response)
        else:
            return {
                'code' : response_code,
                'body' : response
            }

    def parseResponse (self, code, response):
        # 200: Success
        if (code == 200):
            try:
                response = json.loads(response)
                return response
            except ValueError:
                return StrongMonkey.PARSE_ERROR
        # 400: There was an error in the submitted input.
        if (code == 400):
            return StrongMonkey.SUBMIT_ERROR;
        # 401: The authentication failed.
        if (code == 401):
            return StrongMonkey.AUTHENTICATION_FAILED;
        # 404: The requested resource is unavailable.
        if (code == 404):
            return StrongMonkey.RESOURCE_UNAVAILABLE
        # 500: The server ran into an unexpected exception.
        if (code == 500):
            return StrongMonkey.UNEXPECTED_ERROR
        # 501: Unused routes return a 501 exception with an error message.
        if (code == 501):
            return StrongMonkey.UNUSED_ROUTES
        return StrongMonkey.UNKNOWN_ERROR

    def getError (self, error):
        # If not error
        if (not isinstance(error, int)):
            return False
        # Resolve error code
        if error == StrongMonkey.PARSE_ERROR:
            return 'StrongMonkey: Response parse error.'
        if error == StrongMonkey.SUBMIT_ERROR:
            return 'StrongMonkey: There was an error in the submitted input.'
        if error == StrongMonkey.AUTHENTICATION_FAILED:
            return 'StrongMonkey: The authentication failed.'
        if error == StrongMonkey.RESOURCE_UNAVAILABLE:
            return 'StrongMonkey: The requested resource is unavailable.'
        if error == StrongMonkey.UNEXPECTED_ERROR:
            return 'StrongMonkey: The server ran into an unexpected exception.'
        if error == StrongMonkey.UNKNOWN_ERROR:
            return 'StrongMonkey: Unused routes return a 501 exception with an error message.'
        return 'StrongMonkey: Unknown error code.'

    def generateHMAC (self, method, payload, mimetype, datestr, path):
        # Assembly hash message
        message = [
            method,
            payload,
            mimetype,
            datestr,
            StrongMonkey.api_version,
            path
        ]
        message = "\n".join(message)
        # Generate HMAC
        digest = hmac.new(bytes.fromhex(self.keysecret), msg = bytes(message , 'latin-1'), digestmod = hashlib.sha256).digest()
        # Return header
        return 'HMAC ' + self.keyid + ':' + base64.b64encode(digest).decode()

    def jsonStringPrepare (self, vjson, ifnull=None):
        if ((vjson is None) and not (ifnull is None)):
            vjson = ifnull
        if (isinstance(vjson, str)):
            return vjson
        return json.dumps(vjson)
