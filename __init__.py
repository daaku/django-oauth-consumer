import urllib, urlparse, cgi, logging
from functools import wraps
import oauth
from make_request import make_request

from django.conf.urls.defaults import patterns, url
from django.template import RequestContext
from django.shortcuts import render_to_response as render
from django.core.urlresolvers import reverse
from django.dispatch import Signal


class OAuthConsumerApp(object):
    """
    Provides OAuth Consumer functionality for Django.

    """

    def __init__(self, config):
        self.name = config['name']
        self.consumer = oauth.OAuthConsumer(config.get('consumer_key'), config.get('consumer_secret'))
        self.request_token_url = config.get('request_token_url')
        self.authorization_url = config.get('authorization_url')
        self.access_token_url = config.get('access_token_url')

        try:
            method = config.get('signature_method', 'HMAC_SHA1')
            self.sig_method = getattr(oauth, 'OAuthSignatureMethod_' + method)()
        except KeyError:
            raise UnknownSignatureMethod()

        self.got_access_token = Signal(providing_args=["service_provider", "access_token", "request"])

    @property
    def urls(self):
        return patterns('',
            url(r'^success/(?P<oauth_token>[^/]*)/', self.success_auth, name=self.name + '_success'),
        )

    def render(self, template, request, context):
        path = 'django_oauth_consumer/%s/%s.html' % (self.name, template)
        return render(path, context, context_instance=RequestContext(request))

    def make_signed_req(self, url, method='GET', parameters={}, headers={}, token=None):
        """
        Identical to the make_request API, and accepts an additional (optional)
        token parameter. It adds the OAuth Authorization header based on the
        consumer set on this instance.

        """

        parts = urlparse.urlparse(url)
        # drop the query string and use it if it exists
        url = parts.scheme + '://' + parts.netloc + parts.path
        if parts.query != '':
            #FIXME: only using v[0]
            qs_params = dict([(k, v[0]) for k, v in cgi.parse_qs(parts.query).iteritems()])
            qs_params.update(parameters)
            parameters = qs_params

        request = oauth.OAuthRequest.from_consumer_and_token(
                self.consumer,
                token=token,
                http_method=method,
                http_url=url,
                parameters=parameters)
        request.sign_request(self.sig_method, self.consumer, token)
        headers.update(request.to_header())
        return make_request(url, method=method, parameters=parameters, headers=headers)

    def is_valid_signature(self, request):
        # create a new dict with the Authorization key that
        # OAuthRequest.from_request expects.
        if 'HTTP_AUTHORIZATION' in request.META:
            headers = {'Authorization': request.META['HTTP_AUTHORIZATION']}
        else:
            headers = {}

        oauth_request = oauth.OAuthRequest.from_request(
            request.method,
            request.build_absolute_uri(request.path),
            headers,
            dict(request.REQUEST.items()))

        try:
            oauth_signature = oauth_request.get_parameter('oauth_signature')
        except oauth.OAuthError:
            return False # no signature

        if self.sig_method.check_signature(oauth_request, self.consumer, None, oauth_signature):
            return True
        else:
            return False

    def validate_signature(self, view):
        """
        A decorator for Django views to validate incoming signed requests.

        """
        @wraps(view)
        def _do(request, *args, **kwargs):
            if self.is_valid_signature(request):
                return view(request, *args, **kwargs)
            else:
                return self.render('invalid_signature', request)
        return _do

    def require_access_token(self, view):
        """
        A decorator for Django views that require an Access Token. It will make
        the access token available as request.{NAME}_access_token where NAME
        was defined in the instance configuration. If an Access Token is not
        available, it will render a templated called:
            "django_oauth_consumer/{NAME}/need_authorization.html"

        """
        @wraps(view)
        def _do(request, *args, **kwargs):
            access_token_key = self.name + '_access_token'
            if access_token_key in request.session:
                return view(request, *args, **kwargs)
            else:
                response = self.make_signed_req(self.request_token_url)
                body = unicode(response.read(), 'utf8').strip()
                request_token = oauth.OAuthToken.from_string(body)
                request.session[self.name + '_request_token'] = request_token
                qs = urllib.urlencode({
                    'oauth_token': request_token.key,
                    'oauth_callback': request.build_absolute_uri(reverse(self.name + '_success', kwargs={'oauth_token': request_token.key})),
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
        return _do

    def success_auth(self, request, oauth_token=None):
        """
        A Django view to handle a successful OAuth Authorization flow from the
        user's side. The Service Provider redirect returns the user here.

        """
        request_token_key = self.name + '_request_token'
        access_token_key = self.name + '_access_token'

        request_token = request.session[request_token_key]
        if request_token.key != oauth_token:
            log.error('request token in session and url dont match')
        response = self.make_signed_req(self.access_token_url, token=request_token)
        body = unicode(response.read(), 'utf8').strip()
        access_token = oauth.OAuthToken.from_string(body)
        request.session[access_token_key] = access_token
        del request.session[request_token_key]

        self.got_access_token.send(
            sender=self,
            service_provider=self.name,
            access_token=access_token,
            request=request,
        )

        return self.render('successful_authorization', request, {'access_token': access_token})
