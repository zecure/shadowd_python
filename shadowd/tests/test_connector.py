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

import unittest
import shadowd.connector


class TestConnector(unittest.TestCase):
    def test_escape_key(self):
        i = shadowd.connector.Input()

        self.assertEqual(i.escape_key('foo'), 'foo')
        self.assertEqual(i.escape_key('foo|bar'), 'foo\\|bar')
        self.assertEqual(i.escape_key('foo\\|bar'), 'foo\\\\\\|bar')
        self.assertEqual(i.escape_key('foo||bar'), 'foo\\|\\|bar')
        self.assertEqual(i.escape_key('foo\\\\bar'), 'foo\\\\\\\\bar')

    def test_unescape_key(self):
        i = shadowd.connector.Input()

        self.assertEqual(i.unescape_key('foo'), 'foo')
        self.assertEqual(i.unescape_key('foo\\|bar'), 'foo|bar')
        self.assertEqual(i.unescape_key('foo\\\\bar'), 'foo\\bar')
        self.assertEqual(i.unescape_key('foo\\\\\\|bar'), 'foo\\|bar')

    def test_split_path(self):
        i = shadowd.connector.Input()

        test1 = i.split_path('foo')
        self.assertEqual(len(test1), 1)
        self.assertEqual(test1[0], 'foo')

        test2 = i.split_path('foo|bar')
        self.assertEqual(len(test2), 2)
        self.assertEqual(test2[0], 'foo')
        self.assertEqual(test2[1], 'bar')

        test3 = i.split_path('foo\\|bar')
        self.assertEqual(len(test3), 1)
        self.assertEqual(test3[0], 'foo\\|bar')

        test4 = i.split_path('foo\\\\|bar')
        self.assertEqual(len(test4), 2)
        self.assertEqual(test4[0], 'foo\\\\')
        self.assertEqual(test4[1], 'bar')

        test5 = i.split_path('foo\\\\\\|bar')
        self.assertEqual(len(test5), 1)
        self.assertEqual(test5[0], 'foo\\\\\\|bar')

        test6 = i.split_path('foo\\')
        self.assertEqual(len(test6), 1)
        self.assertEqual(test6[0], 'foo\\')
