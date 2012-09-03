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

import argparse
import json
import math
import string
import time

import msgpack
from turnstile import config as turnstile_config
from turnstile import limits
from turnstile import middleware
import webob

from keystone import identity
from keystone import token
from keystone.common import logging
from keystone.common.wsgi import Request
from keystone.exception import Error, TokenNotFound

LOG = logging.getLogger(__name__)


class OverLimitFault(webob.exc.HTTPException):
    """
    Rate-limited request response.
    """
    # NOTE(iartarisi) this is a copy of
    # nova.api.openstack.wsgi.OverLimitFault for scenarios where nova is not
    # installed on the same host as keystone
    def __init__(self, message, details, retry_time):
        """
        Initialize new `OverLimitFault` with relevant information.
        """
        hdrs = OverLimitFault._retry_after(retry_time)
        self.wrapped_exc = webob.exc.HTTPRequestEntityTooLarge(headers=hdrs)
        self.content = {
            "overLimitFault": {
                "code": 413,
                "message": message,
                "details": details,
            },
        }

    @staticmethod
    def _retry_after(retry_time):
        delay = int(math.ceil(retry_time - time.time()))
        retry_after = delay if delay > 0 else 0
        headers = {'Retry-After': '%d' % retry_after}
        return headers

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, request):
        """
        Return the wrapped exception with a serialized body conforming to our
        error format.
        """
        metadata = {"attributes": {"overLimitFault": "code"}}

        self.wrapped_exc.body = json.dumps(self.content)

        return self.wrapped_exc

    
class ParamsDict(dict):
    """
    Special dictionary for use with our URI formatter below.  Unknown
    keys default to '{key}'.
    """

    def __missing__(self, key):
        """
        If the key is unknown, return it surrounded by braces.
        """

        return '{%s}' % key


def keystone_preprocess(midware, environ):
    """
    Pre-process requests to keystone.  The tenant name is extracted from
    the keystone context, and the applicable rate limit class is looked
    up in the database.  Both pieces of data are attached to the request
    environment.  This preprocessor must be present to use the
    KeystoneClassLimit rate limiting class.
    """

    # We may need a formatter later on, so set one up
    fmt = string.Formatter()

    # NOTE(iartarisi) Is this the right context we need for passing around?
    context = environ['openstack.context']  
    try:
        token_id = context['token_id']
        assert token_id
    except (KeyError, AssertionError):
        auth = environ['openstack.params']['auth']
        username = auth['passwordCredentials']['username']
        try:
            identity_api = identity.Manager()
            user_id = identity_api.get_user_by_name(
                context, username)['id']
        except KeyError:
            # couldn't find the username in the database. Maybe we're
            # using a weird keystone backend like 'hybrid' and the
            # user_id is the same as the username
            user_id = username
    else:
        token_api = token.Manager()
        try:
            user_id = token_api.get_token(context, token_id)['user']['id']
        except TokenNotFound as e:
            LOG.warning(e)
            user_id = '<NONE>'

    user_ip = environ['REMOTE_ADDR']
    LOG.info("Found user_id: %s with IP: %s" % (user_id, user_ip))

    id_ip = '%s:%s' % (user_id, user_ip)
    environ['turnstile.keystone.user_id'] = id_ip

    # Now, figure out the rate limit class
    klass = midware.db.get('limit-class:' + id_ip)
    # Automatically create a new class for an ip if it doesn't
    # exist. This will be a clone of the existing 'ip-class'.
    if not klass:
        midware.db.set('limit-class:' + id_ip, 'ip-class')
        klass = 'ip-class'
        
    klass = environ.setdefault('turnstile.keystone.limitclass', klass)
    LOG.debug("Rate limit class: %s" % klass)


class KeystoneClassLimit(limits.Limit):
    """
    Rate limiting class for applying rate limits to combinations of
    Keystone user_ids + IP.  The keystone_limits:keystone_preprocess
    preprocessor must be configured for this limit class to match.
    """

    attrs = dict(
        rate_class=dict(
            desc=('The rate limiting class this limit applies to.  Required.'),
            type=str,
            ),
        )

    def route(self, uri, route_args):
        """
        Filter version identifiers off of the URI.
        """

        if uri.startswith('/v1.1/'):
            return uri[5:]
        elif uri.startswith('/v2/'):
            return uri[3:]

        return uri

    def filter(self, environ, params, unused):
        """
        Determines whether this limit applies to this request and
        attaches the tenant name to the params.
        """

        # Do we match?
        if ('turnstile.keystone.user_id' not in environ or
            'turnstile.keystone.limitclass' not in environ or
            self.rate_class != environ['turnstile.keystone.limitclass']):
            raise limits.DeferLimit()

        # OK, add the tenant to the params
        params['userid'] = environ['turnstile.keystone.user_id']


class KeystoneTurnstileMiddleware(middleware.TurnstileMiddleware):
    """
    Subclass of TurnstileMiddleware.

    This version of TurnstileMiddleware overrides the format_delay()
    method to utilize OverLimitFault.
    """

    def format_delay(self, delay, limit, bucket, environ, start_response):
        """
        Formats the over-limit response for the request.  This variant
        utilizes a copy of Nova's OverLimitFault for consistency with
        Nova's rate-limiting.
        """

        # Build the error message based on the limit's values
        args = dict(
            value=limit.value,
            verb=environ['REQUEST_METHOD'],
            uri=limit.uri,
            unit_string=limit.unit.upper(),
            )
        error = _("Only %(value)s %(verb)s request(s) can be "
                  "made to %(uri)s every %(unit_string)s.") % args

        # Set up the rest of the arguments for wsgi.OverLimitFault
        msg = _("This request was rate-limited.")
        retry = time.time() + delay

        # Convert to a fault class
        fault = OverLimitFault(msg, error, retry)

        # Now let's call it and return the result
        response = fault(environ, start_response)
        LOG.warning(response)
        
        return response

def _limit_class(config, tenant, klass=None):
    """
    Set up or query limit classes associated with tenants.

    :param config: Name of the configuration file, for connecting to
                   the Redis database.
    :param tenant: The ID of the tenant.
    :param klass: If provided, the name of the class to map the tenant
                  to.

    Returns the class associated with the given tenant.
    """

    # Connect to the database...
    db, _limits_key, _control_channel = turnstile_config.Config().get_database()

    # Get the key for the limit class...
    key = 'limit-class:%s' % tenant

    # Now, look up the tenant's current class
    old_klass = db.get(key) or 'default'

    # Do we need to change it?
    if klass and klass != old_klass:
        if klass == 'default':
            # Resetting to the default
            db.delete(key)
        else:
            # Changing to a new value
            db.set(key, klass)

    return old_klass


def limit_class():
    """
    Console script entry point for setting limit classes.
    """

    parser = argparse.ArgumentParser(
        description="Set up or query limit classes associated with tenants.",
        )

    parser.add_argument('config',
                        help="Name of the configuration file, for connecting "
                        "to the Redis database.")
    parser.add_argument('tenant_id',
                        help="ID of the tenant.")
    parser.add_argument('--debug', '-d',
                        dest='debug',
                        action='store_true',
                        default=False,
                        help="Run the tool in debug mode.")
    parser.add_argument('--class', '-c',
                        dest='klass',
                        action='store',
                        default=None,
                        help="If specified, sets the class associated with "
                        "the given tenant ID.")

    args = parser.parse_args()
    try:
        klass = _limit_class(args.config, args.tenant_id, args.klass)

        print "Tenant %s:" % args.tenant_id
        if args.klass:
            print "  Previous rate-limit class: %s" % klass
            print "  New rate-limit class: %s" % args.klass
        else:
            print "  Configured rate-limit class: %s" % klass
    except Exception as exc:
        if args.debug:
            raise
        return str(exc)
