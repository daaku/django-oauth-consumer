django-oauth-consumer
=====================

A `django <http://www.djangoproject.com/>`_ application providing
infrastructure for **consuming** OAuth services. It is **not** for *providing*
OAuth services.

The code is hosted
`here at github <http://github.com/nshah/django-oauth-consumer/tree/master>`_.
The latest code can be downloaded as a
`zip file <http://github.com/nshah/django-oauth-consumer/zipball/master>`_ or a
`tarball <http://github.com/nshah/django-oauth-consumer/tarball/master>`_.

Requires Python 2.6 or newer and:

    - `django <http://github.com/django/django/tree/master>`_
    - `python-make-request <http://code.daaku.org/python-make-request/>`_
    - `python-oauth <http://code.daaku.org/python-oauth/>`_
    - `python-urlencoding <http://code.daaku.org/python-urlencoding/>`_

Can be installed using `pip <http://pip.openplans.org/>`_::

    pip install -r http://code.daaku.org/django-oauth-consumer/reqs

.. toctree::

****************
OAuthConsumerApp
****************

Multiple OAuth services are supported by creating an application for each
service provider you need to access. This application is an instance of
OAuthConsumerApp. It is bound to some configuration and has a name which must
be unique across all OAuthConsumerApp instances.

This application instance gives you the ability to:

    - Make signed requests (2 & 3 legged)
    - Validate incoming (2 legged) signed requests
    - Handle the access token flow

In order to use this application, you must:

    - Create an instance of OAuthConsumerApp
    - Include the urls from that instance in your urlconf
    - *Optional.* Provide some templates. Which one depends on your needs.

.. autoclass:: django_oauth_consumer.OAuthConsumerApp
    :members: store_access_token, get_access_token, start_access_token_flow, require_access_token, make_signed_req, is_valid_signature, validate_signature, need_authorization, success_auth, urls
