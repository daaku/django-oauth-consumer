import urllib, urlparse, cgi, logging
from functools import wraps
import urlencoding
import oauth
import collections
from make_request import make_request

from django.conf.urls.defaults import patterns, url
from django.template import RequestContext
from django.shortcuts import render_to_response as render
from django.core.urlresolvers import reverse, get_callable
from django.dispatch import Signal
from django.http import HttpResponseRedirect


DEFAULT_SIGNATURE_METHOD = 'oauth.signature_method.hmac_sha1.OAuthSignatureMethod_HMAC_SHA1'


class OAuthConsumerApp(object):
    """
    Provides OAuth Consumer functionality for Django.

    """

    def __init__(self, config):
        self.name = config['name']
        self.consumer = {
            'oauth_token': config.get('consumer_key'),
            'oauth_token_secret': config.get('consumer_secret'),
        }
        self.request_token_url = config.get('request_token_url')
        self.authorization_url = config.get('authorization_url')
        self.access_token_url = config.get('access_token_url')
        self.realm = config.get('realm')

        # dynamic constants ;)
        self.NEEDS_AUTH_VIEW_NAME = self.name + '_needs_auth'
        self.SUCCESS_VIEW_NAME = self.name + '_success'
        self.ACCESS_TOKEN_NAME = self.name + '_access_token'
        self.REQUEST_TOKEN_NAME = self.name + '_request_token'

        try:
            self.sig_method = get_callable(config.get('signature_method', DEFAULT_SIGNATURE_METHOD))
        except KeyError:
            raise UnknownSignatureMethod()

        self.got_access_token = Signal(providing_args=["service_provider", "access_token", "request"])

    @property
    def urls(self):
        return patterns('',
            url(r'^auth/', self.need_authorization, name=self.NEEDS_AUTH_VIEW_NAME),
            url(r'^success/(?P<oauth_token>.*)/', self.success_auth, name=self.SUCCESS_VIEW_NAME),
        )

    def render(self, template, request, context):
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
            request.session[self.ACCESS_TOKEN_NAME] = new_token

            self.got_access_token.send(
                sender=self,
                service_provider=self.name,
                access_token=new_token,
                request=request,
            )

            return self.make_signed_req(url, method, content, headers, new_token, request)
        else:
            return response

    def is_valid_signature(self, request):
        """
        Validates the incoming *2 legged* signed request. This is useful for
        signed requests from OpenSocial Containers such as YAP.

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

        """
        @wraps(view)
        def _do(request, *args, **kwargs):
            try:
                self.is_valid_signature(request)
                return view(request, *args, **kwargs)
            except oauth.OAuthError, e:
                logging.info('Invalid Signature')
                return self.render('invalid_signature', request, {'error': e})
        return _do

    def require_access_token(self, view):
        """
        A decorator for Django views that require an Access Token. It will make
        the access token available as request.session['{NAME}_access_token']
        where NAME was defined in the instance configuration. If an Access
        Token is not available, it will redirect to need_authorization.

        """
        @wraps(view)
        def _do(request, *args, **kwargs):
            if self.ACCESS_TOKEN_NAME in request.session:
                return view(request, *args, **kwargs)
            else:
                request.session[self.name + '_next_url'] = request.get_full_path()
                return HttpResponseRedirect(reverse(self.NEEDS_AUTH_VIEW_NAME))

        return _do

    def need_authorization(self, request):
        """
        Fetches a request token from the service provider and renders the
        need_authorization template.

        Renders
            "django_oauth_consumer/{NAME}/need_authorization.html"

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
        return self.render('need_authorization', request, {'authorization_url': url})

    def success_auth(self, request, oauth_token=None):
        """
        A Django view to handle a successful OAuth Authorization flow from the
        user's side. The Service Provider redirect returns the user here.

        """
        request_token = request.session[self.REQUEST_TOKEN_NAME]
        if request_token['oauth_token'] != oauth_token:
            logging.error('request token in session and url dont match')
        response = self.make_signed_req(self.access_token_url, token=request_token)
        body = unicode(response.read(), 'utf8').strip()
        access_token = urlencoding.parse_qs(body)
        request.session[self.ACCESS_TOKEN_NAME] = access_token
        del request.session[self.REQUEST_TOKEN_NAME]

        self.got_access_token.send(
            sender=self,
            service_provider=self.name,
            access_token=access_token,
            request=request,
        )

        return self.render('successful_authorization', request, {
            'access_token': access_token,
            'next_url': request.session[self.name + '_next_url'],
        })
