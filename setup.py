# Shadow Daemon -- Web Application Firewall
#
# Copyright (C) 2015 Hendrik Buchwald <hb@zecure.org>
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

from setuptools import setup

setup(
	name='swd',
	version='0.1',
	description='Python connector for Shadow Daemon web application firewall',
	url='http://github.com/zecure/shadowd_python',
	author='Hendrik Buchwald',
	author_email='hb@zecure.org',
	license='GPL',
	packages=['swd'],
	zip_safe=False
)
