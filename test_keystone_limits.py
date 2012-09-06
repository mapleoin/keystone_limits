# Copyright 2012 SUSE Linux Products Gmbh
# Copyright 2012 Rackspace
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json
import time
import unittest

import msgpack
import stubout
from turnstile import config
from turnstile import limits
from keystone.token.backends.kvs import Token

import keystone_limits


class FakeDatabase(object):
    def __init__(self, fake_db=None):
        self.fake_db = fake_db or {}
        self.actions = []

    def keys(self, pattern):
        self.actions.append(('keys', pattern))

    def get(self, key):
        self.actions.append(('get', key))
        return self.fake_db.get(key)

    def set(self, key, value):
        self.actions.append(('set', key, value))
        self.fake_db[key] = value

    def delete(self, key):
        self.actions.append(('delete', key))
        if key in self.fake_db:
            del self.fake_db[key]


class FakeMiddleware(object):
    def __init__(self, db, limits):
        self.db = db
        self.limits = limits


class FakeObject(object):
    def __init__(self, *args, **kwargs):
        self._args = args
        self.__dict__.update(kwargs)


class FakeLimit(FakeObject):

    def decode(self, key):
        _pre, sep, params = key.partition('/')
        if sep != '/':
            return {}
        return json.loads(params)


class TestKeystoneClassLimit(unittest.TestCase):
    def setUp(self):
        self.lim = keystone_limits.KeystoneClassLimit('db', uri='/spam',
                                                      value=18,
                                                      unit='second')

    def test_route_base(self):
        route_args = {}
        result = self.lim.route('/spam', route_args)

        self.assertEqual(result, '/spam')

    def test_route_v1(self):
        route_args = {}
        result = self.lim.route('/v1.1/spam', route_args)

        self.assertEqual(result, '/spam')

    def test_route_v2(self):
        route_args = {}
        result = self.lim.route('/v2/spam', route_args)

        self.assertEqual(result, '/spam')

    def test_route_v1_base(self):
        route_args = {}
        result = self.lim.route('/v1.1', route_args)

        self.assertEqual(result, '/v1.1')

    def test_route_v2_base(self):
        route_args = {}
        result = self.lim.route('/v2', route_args)

        self.assertEqual(result, '/v2')

    def test_filter(self):
        environ = { 'HTTP_X_REMOTE_ADDR': '127.0.0.1' }
        params = {}
        unused = {}
        self.lim.filter(environ, params, unused)

        self.assertEqual(environ, { 'HTTP_X_REMOTE_ADDR': '127.0.0.1' })
        self.assertEqual(params, dict(original_addr='127.0.0.1'))
        self.assertEqual(unused, {})


class StubKeystoneTurnstileMiddleware(keystone_limits.KeystoneTurnstileMiddleware):
    def __init__(self):
        pass


class TestKeystoneTurnstileMiddleware(unittest.TestCase):
    def setUp(self):
        self.midware = StubKeystoneTurnstileMiddleware()
        self.stubs = stubout.StubOutForTesting()

        def fake_over_limit_fault(msg, err, retry):
            def inner(environ, start_response):
                return (msg, err, retry, environ, start_response)
            return inner

        self.stubs.Set(keystone_limits, 'OverLimitFault', fake_over_limit_fault)
        self.stubs.Set(time, 'time', lambda: 1000000000)

    def tearDown(self):
        self.stubs.UnsetAll()

    def test_format_delay(self):
        lim = FakeObject(value=23, uri='/spam', unit='second')
        environ = dict(REQUEST_METHOD='SPAM')
        start_response = lambda: None
        result = self.midware.format_delay(18, lim, None,
                                           environ, start_response)

        self.assertEqual(result[0], 'This request was rate-limited.')
        self.assertEqual(result[1],
                         'Only 23 SPAM request(s) can be made to /spam '
                         'every SECOND.')
        self.assertEqual(result[2], 1000000018)
        self.assertEqual(id(result[3]), id(environ))
        self.assertEqual(id(result[4]), id(start_response))
