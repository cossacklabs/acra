#!/usr/bin/env python
from distutils.core import setup

setup(name='acra',
      version='1.0.0',
      description='Python binding for creating acra structs',
      author='Dmitriy Kornieiev',
      author_email='lagovas.lagovas@gmail.com',
      packages=['acra', 'acra.django'],
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
