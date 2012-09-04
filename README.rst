================================================
Keystone-specific Rate Limit Class for Turnstile
================================================

This package provides the ``keystone_limits`` Python module, which
contains the ``keystone_preprocess()`` preprocessor, the
``KeystoneClassLimit`` limit class, and the ``KeystoneTurnstileMiddleware``
replacement middleware class, all for use with Turnstile.  These
pieces work together to provide class-based rate limiting integration
with keystone.  To use, you must configure the Turnstile middleware with
the following configuration::

    [filter:turnstile]
    paste.filter_factory = turnstile.middleware:turnstile_filter
    turnstile = keystone_limits:KeystoneTurnstileMiddleware
    preprocess = keystone_limits:keystone_preprocess
    redis.host = <your Redis database host>

Then you must add the `turnstile` filter to your pipelines:

    [pipeline:public_api]
    pipeline = stats_monitoring url_normalize token_auth admin_token_auth xml_body json_body debug ec2_extension user_crud_extension turnstile public_service

    [pipeline:admin_api]
    pipeline = stats_monitoring url_normalize token_auth admin_token_auth xml_body json_body debug stats_reporting ec2_extension s3_extension crud_extension turnstile admin_service

    
Setup Limits
============

In order to read and write limits, you need to use the turnstile
``setup_limits`` and ``load_limits`` commands. Sample configuration and limit files are provided in the `etc/` directory.


    setup_limits etc/keystone_limits.conf etc/default_limits.xml

    dump_limits etc/keystone_limits.conf loaded_limits.xml

    cat loaded_limits.xml

    <?xml version='1.0' encoding='UTF-8'?>
    <limits>
      <limit class="keystone_limits:KeystoneClassLimit">
        <attr name="queries"/>
        <attr name="rate_class">ip-class</attr>
        <attr name="unit">minute</attr>
        <attr name="uri">/tokens</attr>
        <attr name="use"/>
        <attr name="uuid">d8b13e95-4a15-4816-aefd-cb5cef1e78da</attr>
        <attr name="value">2</attr>
        <attr name="verbs">
          <value>POST</value>
        </attr>
      </limit>
    </limits>


Do not modify the ``rate_class`` as it is currently hardcoded.

With the above configuration, the middleware will limit requests to the ``/tokens`` URL to 2 POSTs per minute. These values are configurable in the XML. After you've changed them, they need to be reloaded into the redis database using the ``setup_limits`` command.

Requests are limited per (Keystone user_id + ip combination).
