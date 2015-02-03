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
import sys
import cgi
import Cookie
import urllib

from .connector import Input, Output, Connector

class InputCGI(Input):
	def get_client_ip(self):
		return os.environ.get(self.config.get('client_ip', default='REMOTE_ADDR'))

	def get_caller(self):
		return os.environ.get(self.config.get('caller', default='SCRIPT_FILENAME'))

	def gather_input(self):
		# Reset input.
		self.input = {}

		# Save parameters in input.
		form = cgi.FieldStorage()
		for key in form:
			path = os.environ['REQUEST_METHOD'] + '|' + self.escape_key(key)
			values = form.getlist(key)

			if len(values) > 1:
				for index, value in enumerate(values):
					self.input[path + '|' + str(index)] = value
			else:
				self.input[path] = values[0]

		# Save cookies in input.
		cookie_string = os.environ.get('HTTP_COOKIE')
		if cookie_string:
			cookie = Cookie.SimpleCookie()
			cookie.load(cookie_string)

			for key in cookie:
				self.input['COOKIE|' + self.escape_key(key)] = cookie[key].value

		# Save headers in input.
		for key in os.environ:
			if key[:5] == 'HTTP_':
				self.input['SERVER|' + self.escape_key(key)] = os.environ[key]

	def defuse_input(self, threats):
		# Write all parameters to dict.
		parameters = {}

		form = cgi.FieldStorage()
		for key in form:
			parameters[key] = form.getlist(key)

		# Write all cookies to dict.
		cookies = {}

		cookie_string = os.environ.get('HTTP_COOKIE')
		if cookie_string:
			cookie = Cookie.SimpleCookie()
			cookie.load(cookie_string)

			for key in cookie:
				cookies[key] = cookie[key].value

		# Remove threats.
		for path in threats:
			path_split = self.split_path(path)

			if len(path_split) < 2:
				continue

			key = self.unescape_key(path_split[1])

			if path_split[0] == 'SERVER':
				os.environ[key] = ''
			elif path_split[0] == 'COOKIE':
				cookies[key] = ''
			else:
				if len(path_split) == 3:
					parameters[key][int(path_split[2])] = ''
				else:
					parameters[key][0] = ''

		# Generate new env from the dicts.
		os.environ['QUERY_STRING'] = urllib.urlencode(parameters, True)

		if cookie_string:
			new_cookie_string = ''

			for cookie in cookies:
				new_cookie_string += cookie + '=' + cookies[cookie] + ';'

			os.environ['HTTP_COOKIE'] = new_cookie_string

class OutputCGI(Output):
	def error(self):
		print 'Status: 500 Internal Server Error\r\n\r\n'
		print '<h1>500 Internal Server Error</h1>'

		return None

def main():
	input = InputCGI()
	output = OutputCGI()

	if not Connector().start(input, output):
		sys.exit(0)

main()
