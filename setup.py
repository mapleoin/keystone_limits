#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name='keystone_limits',
    version='0.5.2',
    author='Kevin L. Mitchell, Ionuț Arțăriși',
    author_email='iartarisi@suse.cz',
    description="Keystone-specific rate-limit class for turnstile",
    license='Apache License (2.0)',
    py_modules=['keystone_limits'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Paste',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
        ],
    url='https://github.com/mapleoin/keystone_limits',
    long_description=read('README.rst'),
    entry_points={
        'console_scripts': [
            'limit_class = keystone_limits:limit_class',
            ],
        },
    install_requires=[
        'argparse',
        'msgpack-python',
        'keystone',
        'turnstile',
        ],
    tests_require=[
        'mox',
        ],
    )
