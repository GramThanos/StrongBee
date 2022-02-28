# 
# StrongBee v0.0.3-beta
# 
# Copyright (c) 2021 Grammatopoulos Athanasios-Vasileios
# in collaboration with  Systems Security Laboratory at
# Department of Digital Systems at University of Piraeus
#

import datetime
from flask import Flask, g, current_app
from strongbee.config import Configs
from strongbee.models import db, db_initialize
from strongbee.utilities import rError
from strongbee.api import api

# Select configuration
config = Configs['Active']

# Main Flask Server
class Server(Flask):
	def process_response(self, response):
		# Add custom headers on response
		response.headers['Server'] = config.HEADER_NAME
		# Continue by calling super class
		super(Server, self).process_response(response)
		return response

# Initialize Server
server = Server(__name__)
server.config.from_object(config)
server.server_start_date = datetime.datetime.utcnow()

# Connect Database
db.init_app(server)

# Bind Blueprints
server.register_blueprint(api, url_prefix='/sbfs/rest') # Path for StrongBee FIDO Server (sbfs)
server.register_blueprint(api, url_prefix='/skfs/rest') # Path for StrongKey FIDO Server (skfs) for compatibility

# Listen first request to initialize database
# Can be invoked by just running /sbfs/rest/ping (even Unauthenticated it will do the job)
@server.before_first_request
def init_db():
	db_initialize()

@server.errorhandler(Exception)
def handle_error(error):
	"""
	Handle server response

	:param error: the server error
	:return: Response, HTTP Code
	"""
	# If custom error handled from error
	if hasattr(error, 'code') and hasattr(error, 'description'):
		return error.description, error.code

	# If crash error
	if not current_app.config['DEBUG']:
		return rError('SERVER_EXCEPTION')
	else:
		raise error
		message = error.description if hasattr(error, 'description') else [str(x) for x in error.args]
		response = {
			'error': {
				'type': error.__class__.__name__,
				'message': message
			}
		}
		print(message, response)
		return response, error.code if hasattr(error, 'code') else 500
