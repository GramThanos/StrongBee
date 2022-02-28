# 
# StrongBee v0.0.3-beta
# 
# Copyright (c) 2021 Grammatopoulos Athanasios-Vasileios
# in collaboration with  Systems Security Laboratory at
# Department of Digital Systems at University of Piraeus
#

import os
from strongbee.server import server, config

if __name__ == '__main__':
	# If SSL is enabled
	if config.SSL:
		# If certificate files exists
		if os.path.exists(config.CERT_PUBLIC) and os.path.exists(config.CERT_PRIVATE):
			# Deploy server with HTTPS
			server.run(host=config.HOST, port=config.PORT, ssl_context=(config.CERT_PUBLIC, config.CERT_PRIVATE))
		else:
			# Files not found
			print("Certificate files were not found.")
			print("Try running: openssl req -x509 -newkey rsa:4096 -nodes -out " + config.CERT_PUBLIC + " -keyout " + config.CERT_PRIVATE + " -days 365")
	
	else:
		# Deploy server with HTTP
		server.run(host=config.HOST, port=config.PORT)
