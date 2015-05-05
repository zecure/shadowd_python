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

from .connector import Input, Output, Connector
from werkzeug.datastructures import ImmutableMultiDict

class InputWerkzeug(Input):
	def __init__(self, request):
		self.request = request

	def get_client_ip(self):
		return self.request.environ.get(self.config.get('client_ip', default='REMOTE_ADDR'))

	def get_caller(self):
		return self.request.environ.get(self.config.get('caller', default='PATH_INFO'))

	def gather_input(self):
		# Reset input.
		self.input = {}

		# Save GET parameters in input.
		get_input = self.request.args
		for key in get_input:
			path = 'GET|' + self.escape_key(key)
			values = get_input.getlist(key)

			if len(values) > 1:
				for index, value in enumerate(values):
					self.input[path + '|' + str(index)] = value
			else:
				self.input[path] = values[0]

		# Save POST parameters in input.
		post_input = self.request.form
		for key in post_input:
			path = 'POST|' + self.escape_key(key)
			values = post_input.getlist(key)

			if len(values) > 1:
				for index, value in enumerate(values):
					self.input[path + '|' + str(index)] = value
			else:
				self.input[path] = values[0]

		# Save raw data in input. Has to be done AFTER post_input!
		self.input['DATA|raw'] = self.request.data

		# Save cookies in input.
		for key in self.request.cookies:
			self.input['COOKIE|' + self.escape_key(key)] = self.request.cookies[key]

		# Save headers in input.
		for key in self.request.environ:
			if key[:5] == 'HTTP_':
				self.input['SERVER|' + self.escape_key(key)] = self.request.environ[key]

	def defuse_input(self, threats):
		# Get the input and create copy to make it mutable.
		get_input = self.request.args.copy()
		post_input = self.request.form.copy()
		cookies_input = self.request.cookies.copy()

		# Remove threats.
		for path in threats:
			path_split = self.split_path(path)

			if len(path_split) < 2:
				continue

			key = self.unescape_key(path_split[1])

			if path_split[0] == 'SERVER':
				self.request.environ[key] = u''
			elif path_split[0] == 'COOKIE':
				cookies_input[key] = u''
			elif path_split[0] == 'GET':
				if len(path_split) == 3:
					get_list = get_input.getlist(key)
					get_list[int(path_split[2])] = u''

					get_input.setlist(key, get_list)
				else:
					get_input[key] = u''
			elif path_split[0] == 'POST':
				if len(path_split) == 3:
					post_list = post_input.getlist(key)
					post_list[int(path_split[2])] = u''

					post_input.setlist(key, post_list)
				else:
					post_input[key] = u''
			elif path_split[0] == 'DATA':
				self.request.data = u''

		# Update the GET data.
		self.request.args = ImmutableMultiDict(get_input)

		# Update the POST data.
		self.request.form = ImmutableMultiDict(post_input)

		# Update the cookies.
		self.request.cookies = cookies_input
