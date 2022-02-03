#!/usr/bin/python
""" ad_ldap installation script.

Copyright 2010 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import distutils.core

distutils.core.setup(name='py-ad-ldap',
                     version='2.0',
                     description='A module for manipulating AD through LDAP.',
                     author='Tim Johnson',
                     author_email='timjohnson@google.com',
                     url='http://code.google.com/p/py-ad-ldap',
                     packages=['ad_ldap'],
                     requires=['ldap'],
                     license='Apache 2.0')
