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

import sys
import unittest
import shadowd.werkzeug_connector
import werkzeug.wrappers
import werkzeug.datastructures


class TestWerkzeugConnector(unittest.TestCase):
    def test_get_input(self):
        environ = {
            'wsgi.input': sys.stdin,
            'wsgi.errors': sys.stderr,
            'HTTP_FOO': 'bar',
            'foo': 'bar'
        }
        r = werkzeug.wrappers.Request(environ)
        r.args = werkzeug.datastructures.ImmutableMultiDict({'foo': 'bar'})
        r.form = werkzeug.datastructures.ImmutableMultiDict({'foo': 'bar'})
        r.files = werkzeug.datastructures.ImmutableMultiDict({
            'foo': werkzeug.datastructures.FileStorage(filename='bar')
        })
        r.cookies = {'foo': 'bar'}

        i = shadowd.werkzeug_connector.InputWerkzeug(r)
        i.gather_input()

        input = i.get_input()
        self.assertIn('GET|foo', input)
        self.assertEqual(input['GET|foo'], 'bar')
        self.assertIn('POST|foo', input)
        self.assertEqual(input['POST|foo'], 'bar')
        self.assertIn('COOKIE|foo', input)
        self.assertEqual(input['COOKIE|foo'], 'bar')
        self.assertIn('SERVER|HTTP_FOO', input)
        self.assertEqual(input['SERVER|HTTP_FOO'], 'bar')
        self.assertNotIn('SERVER|foo', input)
        self.assertIn('FILES|foo', input)
        self.assertEqual(input['FILES|foo'], 'bar')

    def test_get_input_array(self):
        environ = {
            'wsgi.input': sys.stdin,
            'wsgi.errors': sys.stderr
        }
        r = werkzeug.wrappers.Request(environ)
        r.args = werkzeug.datastructures.ImmutableMultiDict({'foo': ['bar1', 'bar2']})
        r.form = werkzeug.datastructures.ImmutableMultiDict({'foo': ['bar1', 'bar2']})
        r.files = werkzeug.datastructures.ImmutableMultiDict({'foo': [
            werkzeug.datastructures.FileStorage(filename='bar1'),
            werkzeug.datastructures.FileStorage(filename='bar2')
        ]})

        i = shadowd.werkzeug_connector.InputWerkzeug(r)
        i.gather_input()

        input = i.get_input()
        self.assertIn('GET|foo|0', input)
        self.assertEqual(input['GET|foo|0'], 'bar1')
        self.assertIn('GET|foo|1', input)
        self.assertEqual(input['GET|foo|1'], 'bar2')
        self.assertIn('POST|foo|0', input)
        self.assertEqual(input['POST|foo|0'], 'bar1')
        self.assertIn('POST|foo|1', input)
        self.assertEqual(input['POST|foo|1'], 'bar2')
        self.assertIn('FILES|foo|0', input)
        self.assertEqual(input['FILES|foo|0'], 'bar1')
        self.assertIn('FILES|foo|1', input)
        self.assertEqual(input['FILES|foo|1'], 'bar2')

    def test_defuse_input(self):
        environ = {
            'wsgi.input': sys.stdin,
            'wsgi.errors': sys.stderr,
            'HTTP_FOO': 'bar'
        }
        r = werkzeug.wrappers.Request(environ)
        r.args = werkzeug.datastructures.ImmutableMultiDict({'foo': 'bar'})
        r.form = werkzeug.datastructures.ImmutableMultiDict({'foo': 'bar'})
        r.files = werkzeug.datastructures.ImmutableMultiDict({
            'foo': werkzeug.datastructures.FileStorage(filename='bar')
        })
        r.cookies = {'foo': 'bar'}

        i = shadowd.werkzeug_connector.InputWerkzeug(r)

        threats = ['GET|foo', 'POST|foo', 'COOKIE|foo', 'SERVER|HTTP_FOO', 'FILES|foo']
        self.assertTrue(i.defuse_input(threats))
        self.assertIn('foo', r.args)
        self.assertEqual(r.args['foo'], '')
        self.assertIn('foo', r.form)
        self.assertEqual(r.form['foo'], '')
        self.assertIn('foo', r.cookies)
        self.assertEqual(r.cookies['foo'], '')
        self.assertIn('HTTP_FOO', r.environ)
        self.assertEqual(r.environ['HTTP_FOO'], '')
        self.assertNotIn('foo', r.files)
