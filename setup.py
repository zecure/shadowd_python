#!/usr/bin/env python
#
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
from setuptools import setup

README = os.path.join(os.path.dirname(__file__), 'README.rst')
long_description = open(README).read() + '\n\n'

setup(
	name='shadowd',
	version='1.2.0',
	description='Python connector for the Shadow Daemon web application firewall',
	long_description=long_description,
	url='http://github.com/zecure/shadowd_python',
	author='Hendrik Buchwald',
	author_email='hb@zecure.org',
	license='GPLv2',
	packages=['shadowd'],
	classifiers=[
		'Development Status :: 5 - Production/Stable',
		'Intended Audience :: System Administrators',
		'Environment :: Web Environment',
		'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
		'Programming Language :: Python :: 2',
		'Topic :: Internet :: WWW/HTTP',
		'Topic :: System :: Networking :: Firewalls',
	],
	keywords='waf security shadowd',
)
