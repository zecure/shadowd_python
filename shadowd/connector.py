# Shadow Daemon -- Web Application Firewall
#
# Copyright (C) 2014-2015 Hendrik Buchwald <hb@zecure.org>
#
# This file is part of Shadow Daemon. Shadow Daemon is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import os
import time
import traceback
import ConfigParser
import re
import socket
import ssl
import json
import hmac
import hashlib

SHADOWD_CONNECTOR_VERSION        = '1.2.0-python'
SHADOWD_CONNECTOR_CONFIG         = '/etc/shadowd/connectors.ini'
SHADOWD_CONNECTOR_CONFIG_SECTION = 'shadowd_python'
STATUS_OK                        = 1
STATUS_BAD_REQUEST               = 2
STATUS_BAD_SIGNATURE             = 3
STATUS_BAD_JSON                  = 4
STATUS_ATTACK                    = 5

class Config:
	def __init__(self):
		if os.environ.get('SHADOWD_CONNECTOR_CONFIG'):
			self.file = os.environ.get('SHADOWD_CONNECTOR_CONFIG')
		else:
			self.file = SHADOWD_CONNECTOR_CONFIG

		self.config = ConfigParser.ConfigParser()
		self.config.read(self.file)

		if os.environ.get('SHADOWD_CONNECTOR_CONFIG_SECTION'):
			self.section = os.environ.get('SHADOWD_CONNECTOR_CONFIG_SECTION')
		else:
			self.section = SHADOWD_CONNECTOR_CONFIG_SECTION

	def get(self, key, required = False, default = None):
		try:
			return self.config.get(self.section, key)
		except ConfigParser.NoOptionError:
			if required:
				raise Exception(key + ' in config missing')
			else:
				return default

class Input:
	def set_config(self, config):
		self.config = config

	def get_client_ip(self):
		raise NotImplementedError()

	def get_caller(self):
		raise NotImplementedError()

	def gather_input(self):
		raise NotImplementedError()

	def defuse_input(self, threats):
		raise NotImplementedError()

	def get_input(self):
		return self.input

	def remove_ignored(self, file):
		handler = open(file, 'r')

		if not handler:
			raise Exception('could not open ignore file')

		content = handler.read()
		json_data = json.loads(content)

		handler.close()

		for entry in json_data:
			if not 'path' in entry and 'caller' in entry:
				if self.get_caller() == entry['caller']:
					self.input = {}
					break
			else:
				if 'caller' in entry:
					if self.get_caller() == entry['caller']:
						continue

				if 'path' in entry:
					del self.input[entry['path']]

	def escape_key(self, key):
		return key.replace('\\', '\\\\').replace('|', '\\|')

	def unescape_key(self, key):
		return key.replace('\\\\', '\\').replace('\\|', '|')

	def split_path(self, path):
		output = []
		current = []

		iterator = iter(path)
		for char in iterator:
			if char == '\\':
				try:
					current.append(next(iterator))
				except StopIteration:
					current.append('\\')
			elif char == '|':
				output.append('' . join(current))
				current = []
			else:
				current.append(char)

		output.append('' . join(current))
		return output

class Output:
	def set_config(self, config):
		self.config = config

	def error(self):
		raise NotImplementedError()

	def log(self, message):
		file = self.config.get('log', default='/var/log/shadowd.log')
		handler = open(file, 'a')

		if not handler:
			raise Exception('could not open log file')

		datetime = time.strftime('%Y-%m-%d %H:%M:%S')
		handler.write(datetime + '\t' + message)

		handler.close()

class Connection:
	def send(self, input, host, port, profile, key, ssl_cert):
		connection = None
		connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		if ssl_cert:
			connection = ssl.wrap_socket(
				connection_socket,
				ca_certs=ssl_cert,
				cert_reqs=ssl.CERT_REQUIRED
			)
		else:
			connection = connection_socket

		connection.connect((host, port))

		input_data = {
			'version':   SHADOWD_CONNECTOR_VERSION,
			'client_ip': input.get_client_ip(),
			'caller':    input.get_caller(),
			'input':     input.get_input()
		}

		json_data = json.dumps(input_data)
		connection.sendall(str(profile) + "\n" + self.sign(key, json_data) + "\n" + json_data + "\n")

		output = ''

		while True:
			new_output = connection.recv(1024)

			if not new_output:
				break

			output += new_output

		connection.close()

		return self.parse_output(output)

	def parse_output(self, output):
		data = json.loads(output)

		if data['status'] == STATUS_OK:
			return None
		elif data['status'] == STATUS_BAD_REQUEST:
			raise Exception('bad request')
		elif data['status'] == STATUS_BAD_SIGNATURE:
			raise Exception('bad signature')
		elif data['status'] == STATUS_BAD_JSON:
			raise Exception('bad json')
		elif data['status'] == STATUS_ATTACK:
			return data['threats']
		else:
			raise Exception('processing error')

	def sign(self, key, json):
		return hmac.new(key, json, hashlib.sha256).hexdigest()

class Connector:
	def start(self, input, output):
		config = Config()

		try:
			# Add config for subclasses.
			input.set_config(config)
			output.set_config(config)

			# Collect user input and remove sensitive data.
			input.gather_input()

			ignored = config.get('ignore')
			if ignored:
				input.remove_ignored(ignored)

			# Establish a connection with the server and transmit the data.
			connection = Connection()
			threats = connection.send(
				input,
				config.get('host', default='127.0.0.1'),
				config.get('port', default=9115),
				config.get('profile', required=True),
				config.get('key', required=True),
				config.get('ssl')
			)

			# If observe is not enabled remove threats.
			if not config.get('observe') and threats:
				input.defuse_input(threats)

			# If debug is enabled log threats.
			if config.get('debug') and threats:
				output.log('shadowd: removed threat from client: ' + input.get_client_ip() + '\n')
		except:
			if config.get('debug'):
				tb = traceback.format_exc()
				output.log(tb)

			if not config.get('observe'):
				return output.error()

		return True
