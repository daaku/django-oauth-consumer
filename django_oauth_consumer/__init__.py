from django.conf.urls.defaults import patterns, url
from django.core.urlresolvers import reverse, get_callable
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response as render
from django.template import RequestContext, TemplateDoesNotExist
from functools import wraps
from make_request import make_request
import cgi
import collections
import logging
import oauth
import urlencoding
import urllib
import urlparse


DEFAULT_SIGNATURE_METHOD = 'oauth.signature_method.hmac_sha1.OAuthSignatureMethod_HMAC_SHA1'

class NoAccessToken(Exception):
    """
    Raised when get_access_token cannot find a token.

    """
    pass

class OAuthConsumerApp(object):
    """
    Provides OAuth Consumer functionality for Django. Depending on your use of
    the library, some of these arguments can be ignored. But most likely you'll
    need to supply all of them.

    Arguments:

        `name`
            *Required*. This is used in making this application instance
            unique. Make sure you dont use the same name for multiple instances
            of OAuthConsumerApp.

        `consumer_key`
            The consumer key issued to you by the service provider.
            http://oauth.net/core/1.0/#rfc.section.4.3

        `consumer_secret`
            The consumer secret issued to you by the service provider.
            http://oauth.net/core/1.0/#rfc.section.4.3

        `request_token_url`
            The URL to fetch request tokens from.
            http://oauth.net/core/1.0/#request_urls

        `authorization_url`
            The URL to redirect the user to for obtaining Authorization.
            http://oauth.net/core/1.0/#request_urls

        `access_token_url`
            The URL to exchange the authorized request token for an access
            token.

        `realm`
            Optional realm for the Authorization header.
            http://oauth.net/core/1.0/#rfc.section.5.4.2

        `signature_method`
            A Signature Method for use with the OAuth flow. Defaults to

                oauth.signature_method.hmac_sha1.OAuthSignatureMethod_HMAC_SHA1

    """

    def __init__(self, name, consumer_key=None, consumer_secret=None,
            request_token_url=None, authorization_url=None,
            access_token_url=None, realm=None, signature_method=None):
        """
        Initialize an application instance based on the given configuration.

        """

        self.name = name
        self.consumer = {
            'oauth_token': consumer_key,
            'oauth_token_secret': consumer_secret,
        }
        self.request_token_url = request_token_url
        self.authorization_url = authorization_url
        self.access_token_url = access_token_url
        self.realm = realm

        # dynamic constants ;)
        self.NEEDS_AUTH_VIEW_NAME = name + '_needs_auth'
        self.SUCCESS_VIEW_NAME = name + '_success'
        self.ACCESS_TOKEN_NAME = name + '_access_token'
        self.REQUEST_TOKEN_NAME = name + '_request_token'
        self.NEXT_URL_NAME = name + '_next_url'

        # these are used to decide if the application will do a redirect or
        # show a template with the respective views
        self._has_needs_auth_template = True
        self._has_success_auth_template = True

        try:
            self.sig_method = get_callable(signature_method or DEFAULT_SIGNATURE_METHOD)
        except KeyError:
            raise UnknownSignatureMethod()

    @property
    def urls(self):
        """
        Provides the urls for this application instance. These must be included
        for the access token flow to work.

        """
        return patterns('',
            url(r'^auth/', self.need_authorization, name=self.NEEDS_AUTH_VIEW_NAME),
            url(r'^success/(?P<oauth_token>.*)/', self.success_auth, name=self.SUCCESS_VIEW_NAME),
        )

    def _render(self, template, request, context):
        """
        Helper method to render name specific templates.

        """
        path = 'django_oauth_consumer/%s/%s.html' % (self.name, template)
        return render(path, context, context_instance=RequestContext(request))

    def make_signed_req(self, url, method='GET', content={}, headers={}, token=None, request=None):
        """
        Identical to the make_request API, and accepts an additional (optional)
        token parameter and request object (required if dealing with Scalable
        OAuth service providers). It adds the OAuth Authorization header based
        on the consumer set on this instance. If content not a Mapping object,
        it will be ignored with respect to signing. This means you need to
        either pass the query parameters as a dict/Mapping object, or pass a
        encoded query string as part of the URL which will be extracted and
        included in the signature.

        http://oauth.net/core/1.0/#rfc.section.7

        Arguments:

            `url`
                The URL - query parameters will be parsed out.

            `method`
                The HTTP method to use.

            `content`
                A dict of key/values or string/unicode value.

            `headers`
                A dict of headers.

            `token`
                An optional access token. If this is provided, you will be
                making a 3-legged request. If it is missing, you will be making
                a 2-legged request.

            `request`
                *Optional*. Needed if using Scalable OAuth in order to
                transparently handle access token renewal.
                http://wiki.oauth.net/ScalableOAuth#AccessTokenRenewal

        """

        if isinstance(content, collections.Mapping):
            params = content
        else:
            params = {}

        orequest = oauth.OAuthRequest(url, method, params)
        orequest.sign_request(self.sig_method, self.consumer, token)
        headers['Authorization'] = orequest.to_header(self.realm)
        response = make_request(url, method=method, content=content, headers=headers)

        # check if we got a scalable oauth token_expired error
        # we will fetch a new access token using the oauth_session_handle in
        # the current token and redo the request in this case.
        # FIXME: infinite loop
        www_auth = response.getheader('www-authenticate', None)
        if www_auth and response.status == 401 and 'token_expired' in www_auth:
            response = self.make_signed_req(
                self.access_token_url,
                content={'oauth_session_handle': token['oauth_session_handle']},
                token=token,
                request=request
            )
            body = unicode(response.read(), 'utf8').strip()
            new_token = urlencoding.parse_qs(body)
            self.store_access_token(request, new_token)

            return self.make_signed_req(url, method, content, headers, new_token, request)
        else:
            return response

    def is_valid_signature(self, request):
        """
        Validates the incoming *2 legged* signed request. This is useful for
        signed requests from OpenSocial Containers such as YAP.

        It calls OAuthRequest.validate_signature which throws an OAuthError if
        the signature validation fails.

        """
        oauth_request = oauth.OAuthRequest(
            request.build_absolute_uri(request.path),
            request.method,
            dict(request.REQUEST.items()),
            {'Authorization': request.META.get('HTTP_AUTHORIZATION', '')},
        )
        oauth_request.validate_signature(self.sig_method, self.consumer)

    def validate_signature(self, view):
        """
        A decorator for Django views to validate incoming signed requests.
        This is for *2 legged* signed requests. This is useful for requests
        from OpenSocial Containers such as YAP.

        It will render this template when it recieves an invalid signature:

            `django_oauth_consumer/{NAME}/invalid_signature.html`

        """
        @wraps(view)
        def _do(request, *args, **kwargs):
            try:
                self.is_valid_signature(request)
                return view(request, *args, **kwargs)
            except oauth.OAuthError, e:
                logging.info('Invalid Signature')
                return self._render('invalid_signature', request, {'error': e})
        return _do

    def get_access_token(self, request):
        """
        This can be overridden to allow alternate storage mechanisms.
        Make sure to raise NoAccessToken() if one is not found.

        Default is session based storage.

        """
        if self.ACCESS_TOKEN_NAME in request.session:
            return request.session[self.ACCESS_TOKEN_NAME]
        else:
            raise NoAccessToken()

    def store_access_token(self, request, token):
        """
        This can be overridden to allow alternate storage mechanisms.

        Default is session based storage.

        """
        request.session[self.ACCESS_TOKEN_NAME] = token

    def start_access_token_flow(self, request):
        """
        This triggers the access token flow *without* checking if one already
        exists. That's your job.

        """
        request.session[self.NEXT_URL_NAME] = request.get_full_path()
        return HttpResponseRedirect(reverse(self.NEEDS_AUTH_VIEW_NAME))

    def require_access_token(self, view):
        """
        A decorator for views that require an Access Token. This will ensure
        that you have an access token by automatically triggering the access
        token flow.

        """
        @wraps(view)
        def _do(request, *args, **kwargs):
            try:
                access_token = self.get_access_token(request)
                return view(request, *args, **kwargs)
            except NoAccessToken:
                return self.start_access_token_flow(request)

        return _do

    def need_authorization(self, request):
        """
        The view that triggers the access token flow by sending the user to the
        authorization url. If you wish to show the user a message, you may
        provide a template named:

            `django_oauth_consumer/{NAME}/need_authorization.html`

        The template will be provided an `authorization_url` in the context.

        If you do not provide a template, the user will be redirected there
        immediately.

        """

        response = self.make_signed_req(self.request_token_url)
        body = unicode(response.read(), 'utf8').strip()
        request_token = urlencoding.parse_qs(body)
        request.session[self.name + '_request_token'] = request_token
        qs = urlencoding.compose_qs({
            'oauth_token': request_token['oauth_token'],
            'oauth_callback': request.build_absolute_uri(
                reverse(self.SUCCESS_VIEW_NAME, kwargs={'oauth_token': request_token['oauth_token']})),
        })
        url = self.authorization_url
        if '?' in url:
            if url[-1] == '&':
                url += qs
            else:
                url += '&' + qs
        else:
            url += '?' + qs

        if self._has_needs_auth_template:
            try:
                return self._render('need_authorization', request, {'authorization_url': url})
            except TemplateDoesNotExist:
                self._has_needs_auth_template = False
        return HttpResponseRedirect(url)

    def success_auth(self, request, oauth_token=None):
        """
        The view that handles a successful OAuth Authorization flow from the
        user's side. The Service Provider redirect returns the user here.
        If you wish to show the user a message here before continuing to the
        original URL that triggered the access token flow, you may provide a
        template named:

            `django_oauth_consumer/{NAME}/successful_authorization.html`

        The template will be provided the `access_token` and the `next_url`
        (the original URL the user visited that triggered the access token
        flow).

        If you do not provide a template, the view will simply redirect the
        user back to the original URL.

        """
        request_token = request.session[self.REQUEST_TOKEN_NAME]
        if request_token['oauth_token'] != oauth_token:
            logging.error('request token in session and url dont match')
        response = self.make_signed_req(self.access_token_url, token=request_token)
        body = unicode(response.read(), 'utf8').strip()
        access_token = urlencoding.parse_qs(body)
        self.store_access_token(request, access_token)
        del request.session[self.REQUEST_TOKEN_NAME]
        next_url = request.session.pop(self.NEXT_URL_NAME)

        if self._has_success_auth_template:
            try:
                return self._render('successful_authorization', request, {
                    'access_token': access_token,
                    'next_url': next_url,
                })
            except TemplateDoesNotExist:
                self._has_success_auth_template = False
        return HttpResponseRedirect(next_url)
