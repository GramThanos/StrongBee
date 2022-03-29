# 
# StrongBee v0.0.3-beta
# 
# Copyright (c) 2021 Grammatopoulos Athanasios-Vasileios
# in collaboration with  Systems Security Laboratory at
# Department of Digital Systems at University of Piraeus
#

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from strongbee.config import Config
import datetime, binascii, hashlib, hmac, base64, json


# SQLAlchemy Database Object
db = SQLAlchemy()

"""
SQLAlchemy Models
Define the structure of each table of the database
Tables are not all on the same databases
"""

class APIUser(db.Model):
	"""
	API Users Model
	"""

	# Set SQLAlchemi parameters
	__bind_key__ = 'api'
	__tablename__ = 'api_users'
	
	# Table Schema
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(128), unique=True, nullable=False)
	password_hash = db.Column(db.String(128), nullable=False)
	
	def __repr__(self):
		# Define how to print
		return "<APIUser(username='%s')>" % (self.username,)


class APICredential(db.Model):
	"""
	API Credentials Model
	"""

	# Set SQLAlchemi parameters
	__bind_key__ = 'api'
	__tablename__ = 'api_credentials'
	
	# Table Schema
	id = db.Column(db.Integer, primary_key=True)
	keyid = db.Column(db.String(128), unique=True, nullable=False)
	keysecret = db.Column(db.String(128), nullable=False)
	
	def __repr__(self):
		# Define how to print
		return "<APICredential(keyid='%s')>" % (self.keyid,)


class PublicKey(db.Model):
	"""
	API PublicKeys Model
	"""

	# Set SQLAlchemi parameters
	__bind_key__ = 'keys'
	__tablename__ = 'publickeys'

	# Table Schema
	id = db.Column(db.Integer, primary_key=True)
	keyid = db.Column(db.String(512), unique=True, nullable=False)
	status = db.Column(db.Text, nullable=False)
	username = db.Column(db.Text, nullable=False)
	displayname = db.Column(db.Text, nullable=False)
	keydata = db.Column(db.Text, nullable=False)
	create_date = db.Column(db.Text, nullable=False)
	create_location = db.Column(db.Text, nullable=False)
	modify_date = db.Column(db.Text, nullable=False)
	last_used_location = db.Column(db.Text, nullable=False)
	metadata_version = db.Column(db.Text, nullable=False)
	metadata_origin = db.Column(db.Text, nullable=False)

	def __repr__(self):
		# Define how to print
		return "<PublicKey(keyid='%s', status='%s', username='%s')>" % (self.keyid, self.status, self.username)


class Domain(db.Model):
	"""
	API Domains Model
	"""

	# Set SQLAlchemi parameters
	__bind_key__ = 'keys'
	__tablename__ = 'domains'
	
	# Table Schema
	did = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(256), unique=True, nullable=False)
	
	def __repr__(self):
		# Define how to print
		if self.did:
			return "<Domain(did='%d', name='%s')>" % (self.did, self.name)
		return "<Domain(name='%s')>" % (self.name,)


class State(db.Model):
	"""
	API States Model
	"""

	# Set SQLAlchemi parameters
	__bind_key__ = 'cache'
	__tablename__ = 'states'

	# Table Schema
	id = db.Column(db.Integer, primary_key=True)
	type = db.Column(db.String(64), nullable=False)
	challenge = db.Column(db.String(256), unique=True, nullable=False)
	username = db.Column(db.Text, nullable=False)
	expiration = db.Column(db.Integer, nullable=False)
	state = db.Column(db.Text, nullable=False)
	
	def __repr__(self):
		# Define how to print
		return "<State(type='%s', challenge='%s', username='%s', expiration='%d', state='%s')>" % (
			self.type, self.challenge, self.username, self.expiration, self.state)

	def getState(self):
		return json.loads(self.state)

	def setState(self, state):
		self.state = json.dumps(state)


"""
Models Handlers
These functions can be used to manage the database models
"""

class Domains(object):
	"""
	Domains Handler
	"""

	@staticmethod
	def create(name, commit=True):
		"""
		Create a domain

		:param name: the domain name to be created
		:param commit: commit or not the data to the database
		"""
		dn = Domain(name=name)
		db.session.add(dn)
		if commit:
			return db.session.commit()
		return True

	@staticmethod
	def getById(did):
		"""
		Retrieve a domain by it's did

		:param did: the domain's did
		:return: the Domain of the database
		"""
		return Domain.query.filter_by(did=did).first()

	@staticmethod
	def getByName(name):
		"""
		Retrieve a domain by it's name

		:param name: the domain's name
		:return: the Domain of the database
		"""
		return Domain.query.filter_by(name=name).first()


class PublicKeys(object):
	"""
	Domains Handler
	"""

	@staticmethod
	def create(keyid, username, displayname, keydata, create_location, metadata_origin, commit=True):
		"""
		Create a new PublicKey (created through a registration)

		:param keyid: the keyid of the PublicKey
		:param username: the username of the PublicKey
		:param displayname: the displayname of the PublicKey
		:param keydata: the keydata of the PublicKey
		:param create_location: the create_location of the PublicKey
		:param metadata_origin: the metadata_origin of the PublicKey
		:param commit: optionally commit or not the changes
		"""
		now_date = round(datetime.datetime.timestamp(datetime.datetime.now()) * 1000)
		pk = PublicKey(
			keyid=keyid,
			status='Active',
			username=username,
			displayname=displayname,
			keydata=keydata,
			create_date=now_date,
			create_location=create_location,
			modify_date=now_date,
			last_used_location=create_location,
			metadata_version='1.0',
			metadata_origin=metadata_origin
		)
		db.session.add(pk)
		if commit:
			return db.session.commit()
		return True

	@staticmethod
	def getByUsername(username, status = None):
		"""
		Retrieve PublicKey of a user

		:param username: the user's username
		:param status: optionally filter PublicKeys by their status
		:return: the list of PublicKeys
		"""
		# If no need to filter by status
		if status == None:
			return PublicKey.query.filter_by(username=username).all()
		
		# If is needed to filter by status
		else:
			# Parse the status value
			status = 'Active' if status else 'Inactive'
			return PublicKey.query.filter_by(username=username, status=status).all()

	@staticmethod
	def getById(keyid):
		"""
		Retrieve a PublicKey by its keyid

		:param keyid: the keyid of the PublicKey
		:return: the PublicKey
		"""
		return PublicKey.query.filter_by(keyid=keyid).first()

	@staticmethod
	def deleteById(keyid, commit=True):
		"""
		Delete a PublicKey by its keyid

		:param keyid: the keyid of the PublicKey
		:param commit: optionally commit or not the changes
		:return: True/False if the operation was successful
		"""
		pk = PublicKey.query.filter_by(keyid=keyid).first()
		# If PublicKey was found
		if pk:
			db.session.delete(pk)
			if commit:
				db.session.commit()
			return True
		# If PublicKey was not found
		return False

	@staticmethod
	def updateById(keyid, status, modify_location, displayname, commit=True):
		"""
		Update a PublicKey by its keyid

		:param keyid: the keyid of the PublicKey
		:param status: the new status to set
		:param modify_location: the new modify_location to set
		:param displayname: the new displayname to set
		:param commit: optionally commit or not the changes
		:return: True/False if the operation was successful
		"""
		pk = PublicKey.query.filter_by(keyid=keyid).first()
		if pk:
			pk.status = status
			pk.modify_location = modify_location
			pk.displayname = displayname
			if commit:
				db.session.commit()
			return True
		return False


class States(object):
	"""
	States Handler
	"""

	@staticmethod
	def create(stype, challenge, username, expiration, state, commit=True):
		"""
		Create a new State (generated through PreAuthentication or PreRegistration)

		:param stype: the type of the State (we separate authentications from registrations)
		:param challenge: the challenge of the State
		:param username: the username of the State (bind username to the state)
		:param expiration: the expiration of the State
		:param state: the actual value object of the State (this value is generated by the FIDO2 library)
		:param commit: optionally commit or not the changes
		"""
		# Parse expiration to time-stamp in ms
		exp = round(datetime.datetime.timestamp(expiration) * 1000)
		# Create state
		st = State(
			type=stype,
			challenge=challenge,
			username=username,
			expiration=exp
		)
		# Set state value to the state
		st.setState(state)
		# Add state on the database
		db.session.add(st)
		if commit:
			return db.session.commit()
		return True

	@staticmethod
	def clean(commit=True):
		"""
		Delete expired states from the database

		:param commit: optionally commit or not the changes
		:return: number of deleted states
		"""
		# Get current time-stamp in ms
		exp = round(datetime.datetime.timestamp(datetime.datetime.now()) * 1000)
		# Find expired states
		st = State.query.filter(State.expiration < exp).all()
		# Delete states and return number of deleted states
		if len(st) > 0:
			for s in st:
				db.session.delete(s)
			if commit:
				db.session.commit()
			return len(st)
		return 0

	@staticmethod
	def deleteAndClean(stype, challenge, commit=True):
		"""
		Delete state by challenge and at the same time

		:param stype: the type of the State (we separate authentications from registrations)
		:param challenge: the challenge of the State
		:param commit: optionally commit or not the changes
		:return: number of deleted states
		"""
		# Get current time-stamp in ms
		exp = round(datetime.datetime.timestamp(datetime.datetime.now()) * 1000)
		# Find the requested state and other expired states
		st = State.query.filter((State.expiration < exp) | ((State.type == stype) & (State.challenge == exp))).all()
		# Delete states and return number of deleted states
		if len(st) > 0:
			for s in st:
				db.session.delete(s)
			if commit:
				db.session.commit()
			return len(st)
		return 0

	@staticmethod
	def get(stype, challenge):
		"""
		Get valid state by challenge (expired states will not be returned)

		:param stype: the type of the State (we separate authentications from registrations)
		:param challenge: the challenge of the State
		:param commit: optionally commit or not the changes
		:return: state
		"""
		# Get current time-stamp in ms
		exp = round(datetime.datetime.timestamp(datetime.datetime.now()) * 1000)
		st = State.query.filter((State.type == stype) & (State.challenge == challenge) & (State.expiration > exp)).first()
		return st


class APIUsers(object):
	"""
	Domains Handler
	"""

	def create(username, password, commit=True):
		"""
		Create an API User

		:param username: the username of the user
		:param password: the password of the user
		:param commit: optionally commit or not the changes
		"""
		user = APIUser(
			username=username,
			password_hash=APIUsers.passwordHash(password)
		)
		db.session.add(user)
		if commit:
			return db.session.commit()
		return True

	def authenticate(username, password):
		"""
		Authenticate an API User by password

		:param username: the username of the user
		:param password: the password of the user
		:return: True/False
		"""
		user = PublicKey.query.filter_by(username=username).first()
		# If user found
		if user:
			# Verify the given password
			return APIUsers.passwordVerify(user.password_hash, password)
		return False

	# Hash a password for storing.
	def passwordHash(password, alg='sha256'):
		"""
		Hash a password to be saved on the database
		TODO: The passwordHash and passwordVerify needs to be improved 
			  so that they work with multiple algorithms/salts.
			  For example when saving the output an other format should be used
			  like "$<ALGORITHM_ID>$<COST_IN_FORMAT>$<BASE64_ENCODED_SALT><BASE64_ENCODED_HASH>$"
			  or better use the bCrypt library

		:param password: the password to hash
		:param alg: optionally the algorithm to be used
		:return: True/False
		"""
		# Generate random salt
		salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii') # TODO: the hash function here is not needed
		# Generate hash using pbkdf2_hmac
		pwdhash = hashlib.pbkdf2_hmac(alg, password.encode('utf-8'), salt, 100000)
		pwdhash = binascii.hexlify(pwdhash)
		# Return salt and hash
		return (salt + pwdhash).decode('ascii')

	# Verify a stored password against one provided by user
	def passwordVerify(stored_hash, provided_password, alg='sha256'):
		"""
		Verify if the password is the same with the one saved
		TODO: Check passwordHash's TODO

		:param password: the password to hash
		:param alg: optionally the algorithm to be used
		:return: True/False
		"""
		# Retrieve salt
		salt = stored_hash[:64]
		# Retrieve hash
		stored_hash = stored_hash[64:]
		# Recalculate hash of the given pass
		pwdhash = hashlib.pbkdf2_hmac(alg, provided_password.encode('utf-8'), salt.encode('ascii'), 100000)
		pwdhash = binascii.hexlify(pwdhash).decode('ascii')
		# Check if the given password results in the same hash
		return pwdhash == stored_hash


class APICredentials(object):
	"""
	Domains Handler
	"""

	def create(keyid, keysecret, commit=True):
		"""
		Create API Credentials

		:param keyid: the keyid of the Credentials
		:param keysecret: the keysecret of the Credentials
		:param commit: optionally commit or not the changes
		"""
		cr = APICredential(
			keyid=keyid,
			keysecret=keysecret
		)
		db.session.add(cr)
		if commit:
			return db.session.commit()
		return True

	def authenticate(keyid, hashtag, payload):
		"""
		Authenticate API Credentials by signature

		:param keyid: the keyid of the credentials
		:param hashtag: the signature given on the request
		:param payload: the payload given on the request
		:return: True/False
		"""
		cr = APICredential.query.filter_by(keyid=keyid).first()
		# If credentials found
		if cr:
			# Verify the given signature
			return APICredentials.HMACVerify(hashtag, cr.keysecret, payload)
		return False

	def HMACVerify(provided_hashtag, keysecret, payload):
		"""
		Verify the signature

		:param provided_hashtag: the signature given
		:param keysecret: the secret to generate the signature
		:param payload: the payload that was signed
		:return: True/False
		"""
		# Generate HMAC signature for the payload using the secret key
		digest = hmac.new(bytes.fromhex(keysecret), msg = bytes(payload , 'latin-1'), digestmod = hashlib.sha256).digest()
		generated_hashtag = base64.b64encode(digest).decode()
		# Check if signatures are the same
		if generated_hashtag == provided_hashtag:
			return True
		return False



def db_initialize():
	"""
	Initialize Databases
	"""
	# Create all schemes on the databases
	db.create_all()
	
	# Create Domains
	try:
		Domains.create('fido2app.gramthanos.com', False)
		Domains.create('strongmonkey.gramthanos.com', False)
		Domains.create('unipi.gr', False)
		db.session.commit()
	except Exception as e:
		db.session.rollback()
		pass

	# Create API Credentials
	try:
		APICredentials.create('162a5684336fa6e7', '7edd81de1baab6ebcc76ebe3e38f41f4', False)
		APICredentials.create('b55938050b05019a', '40e5b172b3d01c204f5e301d132e4fa6', False)
		db.session.commit()
	except Exception as e:
		db.session.rollback()
		pass
