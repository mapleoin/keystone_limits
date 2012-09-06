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
import StringIO
import sys
import time
import unittest

import argparse
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


class TestPreprocess(unittest.TestCase):
    def setUp(self):
        self.stubs = stubout.StubOutForTesting()

        self.stubs.Set(time, 'time', lambda: 1000000000)
        self.stubs.Set(msgpack, 'loads', lambda x: x)

    def tearDown(self):
        self.stubs.UnsetAll()

    def test_unknown_user(self):
        db = FakeDatabase()
        midware = FakeMiddleware(db, [])
        environ = {
            'openstack.context': dict(token_id='tokenid'),
            'REMOTE_ADDR': '127.0.0.1',
            }
        keystone_limits.keystone_preprocess(midware, environ)

        self.assertEqual(environ, {
                'REMOTE_ADDR': '127.0.0.1',
                'openstack.context': dict(token_id='tokenid'),
                'turnstile.keystone.limitclass': 'ip-class',
                'turnstile.keystone.user_id': '<NONE>:127.0.0.1',
                })
        self.assertEqual(db.actions, [
                ('get', 'limit-class:<NONE>:127.0.0.1'),
                ('set', 'limit-class:<NONE>:127.0.0.1', 'ip-class')])

    def test_user_id_existing_limit_class(self):
        db = FakeDatabase({'limit-class:1:127.0.0.1': 'ip-class'})
        midware = FakeMiddleware(db, [])
        environ = {
            'openstack.context': dict(token_id='tokenid'),
            'REMOTE_ADDR': '127.0.0.1',
            }
        self.stubs.Set(Token, 'get_token',
                       lambda x, y: {'user': {'id': 1}})
        keystone_limits.keystone_preprocess(midware, environ)

        self.assertEqual(environ['turnstile.keystone.user_id'], '1:127.0.0.1')
        self.assertEqual(environ['turnstile.keystone.limitclass'], 'ip-class')
        self.assertEqual(db.actions, [('get', 'limit-class:1:127.0.0.1')])

    def test_user_id(self):
        db = FakeDatabase()
        midware = FakeMiddleware(db, [])
        environ = {
            'openstack.context': dict(token_id='tokenid'),
            'REMOTE_ADDR': '127.0.0.1',
            }
        self.stubs.Set(Token, 'get_token',
                       lambda x, y: {'user': {'id': 1}})
        keystone_limits.keystone_preprocess(midware, environ)

        self.assertEqual(environ['turnstile.keystone.user_id'], '1:127.0.0.1')
        self.assertEqual(environ['turnstile.keystone.limitclass'], 'ip-class')
        self.assertEqual(db.actions, [
                ('get', 'limit-class:1:127.0.0.1'),
                ('set', 'limit-class:1:127.0.0.1', 'ip-class'),
                ])

    def test_class_no_override(self):
        db = FakeDatabase({'limit-class:1:127.0.0.1': 'lim_class'})
        midware = FakeMiddleware(db, [])
        environ = {
            'openstack.context': dict(token_id='tokenid'),
            'REMOTE_ADDR': '127.0.0.1',
            'turnstile.keystone.limitclass': 'override',
            }
        self.stubs.Set(Token, 'get_token',
                       lambda x, y: {'user': {'id': 1}})
        keystone_limits.keystone_preprocess(midware, environ)

        self.assertEqual(environ['turnstile.keystone.user_id'], '1:127.0.0.1')
        self.assertEqual(environ['turnstile.keystone.limitclass'], 'override')
        self.assertEqual(db.actions, [('get', 'limit-class:1:127.0.0.1')])


class TestKeystoneClassLimit(unittest.TestCase):
    def setUp(self):
        self.lim = keystone_limits.KeystoneClassLimit('db', uri='/spam',
                                                      value=18,
                                                      unit='second',
                                                      rate_class='lim_class')

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

    def test_filter_noclass(self):
        environ = {
            'turnstile.keystone.user_id': 'user1',
            }
        params = {}
        unused = {}
        self.assertRaises(limits.DeferLimit,
                          self.lim.filter, environ, params, unused)
        self.assertEqual(environ, {
                'turnstile.keystone.user_id': 'user1',
                })
        self.assertEqual(params, {})
        self.assertEqual(unused, {})

    def test_filter_nouser(self):
        environ = {
            'turnstile.keystone.limitclass': 'lim_class',
            }
        params = {}
        unused = {}
        self.assertRaises(limits.DeferLimit,
                          self.lim.filter, environ, params, unused)

        self.assertEqual(environ, {
                'turnstile.keystone.limitclass': 'lim_class',
                })
        self.assertEqual(params, {})
        self.assertEqual(unused, {})

    def test_filter_wrong_class(self):
        environ = {
            'turnstile.keystone.limitclass': 'spam',
            'turnstile.keystone.user_id': 'user1',
            }
        params = {}
        unused = {}
        self.assertRaises(limits.DeferLimit,
                          self.lim.filter, environ, params, unused)

        self.assertEqual(environ, {
                'turnstile.keystone.limitclass': 'spam',
                'turnstile.keystone.user_id': 'user1',
                })
        self.assertEqual(params, {})
        self.assertEqual(unused, {})

    def test_filter(self):
        environ = {
            'turnstile.keystone.limitclass': 'lim_class',
            'turnstile.keystone.user_id': 'user1',
            }
        params = {}
        unused = {}
        self.lim.filter(environ, params, unused)

        self.assertEqual(environ, {
                'turnstile.keystone.limitclass': 'lim_class',
                'turnstile.keystone.user_id': 'user1',
                })
        self.assertEqual(params, dict(userid='user1'))
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
