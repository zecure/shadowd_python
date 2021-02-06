# Shadow Daemon -- Web Application Firewall
#
# Copyright (C) 2014-2021 Hendrik Buchwald <hb@zecure.org>
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
import unittest

os.environ['SHADOWD_NO_AUTOLOAD'] = '1'
import shadowd.cgi_connector


class TestCgiConnector(unittest.TestCase):
    def test_get_input(self):
        os.environ['REQUEST_METHOD'] = 'GET'
        os.environ['QUERY_STRING'] = 'foo=bar'
        os.environ['HTTP_COOKIE'] = 'foo=bar'
        os.environ['HTTP_FOO'] = 'bar'
        os.environ['foo'] = 'bar'

        i = shadowd.cgi_connector.InputCGI()
        i.gather_input()

        input = i.get_input()
        self.assertIn('GET|foo', input)
        self.assertEqual(input['GET|foo'], 'bar')
        self.assertIn('COOKIE|foo', input)
        self.assertEqual(input['COOKIE|foo'], 'bar')
        self.assertIn('SERVER|HTTP_FOO', input)
        self.assertEqual(input['SERVER|HTTP_FOO'], 'bar')
        self.assertNotIn('SERVER|foo', input)

    def test_get_input_array(self):
        os.environ['REQUEST_METHOD'] = 'GET'
        os.environ['QUERY_STRING'] = 'foo=bar1&foo=bar2'

        i = shadowd.cgi_connector.InputCGI()
        i.gather_input()

        input = i.get_input()
        self.assertIn('GET|foo|0', input)
        self.assertEqual(input['GET|foo|0'], 'bar1')
        self.assertIn('GET|foo|1', input)
        self.assertEqual(input['GET|foo|1'], 'bar2')

    def test_defuse_input(self):
        os.environ['REQUEST_METHOD'] = 'GET'
        os.environ['QUERY_STRING'] = 'foo=bar'
        os.environ['HTTP_COOKIE'] = 'foo=bar'
        os.environ['HTTP_FOO'] = 'bar'

        i = shadowd.cgi_connector.InputCGI()

        threats1 = ['GET|foo', 'COOKIE|foo', 'SERVER|HTTP_FOO']
        self.assertTrue(i.defuse_input(threats1))
        self.assertEqual(os.environ['QUERY_STRING'], 'foo=')
        self.assertEqual(os.environ['HTTP_COOKIE'], 'foo=;')
        self.assertEqual(os.environ['HTTP_FOO'], '')

        threats2 = ['FILES|foo']
        self.assertFalse(i.defuse_input(threats2))
