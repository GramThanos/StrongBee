# 
# StrongBee v0.0.3-beta
# 
# Copyright (c) 2021 Grammatopoulos Athanasios-Vasileios
# in collaboration with  Systems Security Laboratory at
# Department of Digital Systems at University of Piraeus
#
# Server Configuration
#

import os

class Config(object):
	# Server Options
	PORT = 8181
	HOST = '0.0.0.0'
	
	# Server Info
	INFO = {}
	INFO['NAME'] = 'StrongBee';
	INFO['VERSION'] = 'v0.0.3-beta';
	INFO['AUTHOR'] = 'GramThanos & UNIPI';
	INFO['DESCRIPTION'] = INFO['NAME'] + ' FIDO2 Server ' + INFO['VERSION']
	HEADER_NAME = INFO['NAME'] + ' ' + INFO['VERSION']

	# FILES FOLDER
	BASEDIR = os.path.dirname(os.path.abspath(__file__))

	# SSL
	SSL = True
	CERT_PUBLIC = os.path.join(BASEDIR, 'certificate.public.pem')
	CERT_PRIVATE = os.path.join(BASEDIR, 'certificate.private.pem')
	# openssl req -x509 -newkey rsa:4096 -nodes -out certificate.public.pem -keyout certificate.private.pem -days 365


	# SQL Alchemy
	SQLALCHEMY_BINDS = {
		'keys':		'sqlite:///' + os.path.join(BASEDIR, 'database.keys.db'),
		'api':		'sqlite:///' + os.path.join(BASEDIR, 'database.api.db'),
		'cache':	'sqlite:///:memory:'
	}
	SQLALCHEMY_TRACK_MODIFICATIONS = False

	# Default configuration flags
	DEBUG = False
	TESTING = False
	VERBOSE_ERRORS = False

class ProductionConfig(Config):
    pass

class DevelopmentConfig(Config):
    DEBUG = True
    VERBOSE_ERRORS = True

class TestingConfig(Config):
    TESTING = True


# Add all configurations on a dictionary
Configs = {
	'Production':	ProductionConfig,
	'Development':	DevelopmentConfig,
	'Testing':		TestingConfig,

	# The active Config, change this to change the server behavior
	'Active': DevelopmentConfig # ProductionConfig or DevelopmentConfig
}
