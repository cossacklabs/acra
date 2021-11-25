# Copyright 2016, Cossack Labs Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#!/usr/bin/env python
from setuptools import setup

setup(name='acrawriter',
      version='1.0.3',
      description='AcraWriter library for Python: encrypts data into AcraStructs, allowing Acra to decrypt it',
      author='Cossack Labs',
      author_email='dev@cossacklabs.com',
      url='https://github.com/cossacklabs/acra/',
      packages=['acrawriter', 'acrawriter.django', 'acrawriter.sqlalchemy'],
      install_requires=[
          'pythemis',
      ],
      classifiers=[
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.2',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
      ],)
