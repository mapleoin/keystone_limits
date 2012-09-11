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
import math
import time

import msgpack
from turnstile import config as turnstile_config
from turnstile import limits
from turnstile import middleware
import webob

from keystone import config
from keystone import identity
from keystone import token
from keystone.common import logging
from keystone.common.wsgi import Request
from keystone.exception import Error, TokenNotFound

LOG = logging.getLogger(__name__)
CONF = config.CONF


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


def keystone_preprocess(midware, environ):
    """
    Pre-process requests to keystone. Figure out if this is an
    authentication request. Two authentication methods are recognized:
     - token based - these requests will contain the 'X-Auth-Token' or
       'X-Storage-Token' headers
     - credentials - this is done with a POST request to '/tokens'
    """
    if ('HTTP_X_AUTH_TOKEN' in environ or
        'HTTP_X_STORAGE_TOKEN' in environ or
        (environ['PATH_INFO'] == '/tokens' and
         environ['REQUEST_METHOD'] == 'POST')):
        environ['keystone.auth_request'] = True
    
class KeystoneClassLimit(limits.Limit):
    """
    Rate limiting class for applying rate limits to combinations of
    Keystone user_ids + IP.
    """

    attrs = dict(
        rate_class=dict(
            desc=('The rate limiting class this limit applies to. Required.'),
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
        Attaches the original_addr to the parameters considered for filtering
        """
        # stop filtering if we haven't already validated this request
        if environ.get('keystone.auth_request') is None:
            raise limits.DeferLimit()

        remote_addr = (environ.get('HTTP_X_REMOTE_ADDR')
                       or environ['REMOTE_ADDR'])
        if CONF.verbose:
            LOG.info('Filtering request from: %s with rate class: %s' %
                     (remote_addr, self.rate_class))

        params['original_addr'] = remote_addr


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
