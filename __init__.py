import urllib, urlparse, cgi, logging
import oauth
from make_request import make_request

from django.conf.urls.defaults import patterns, url
from django.http import HttpResponse
from django.shortcuts import render_to_response as render
from django.core.urlresolvers import reverse
from django_oauth_consumer.models import OAuthUserToken


class OAuthConsumerApp(object):
    """
    Provides OAuth Consumer functionality for Django.

    """

    def __init__(self, config):
        self.name = config['name']

        self.consumer_key = config['consumer_key']
        self.consumer_secret = config['consumer_secret']

        self.request_token_url = config.get('request_token_url')
        self.authorization_url = config.get('authorization_url')
        self.access_token_url = config.get('access_token_url')

        self.consumer = oauth.OAuthConsumer(self.consumer_key, self.consumer_secret)
        self.sig_method = oauth.OAuthSignatureMethod_HMAC_SHA1()

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

    def validate_signature(self, view):
        """
        A decorator for Django views to require a signed request.

        """

        def _do(*args, **kwargs):
            logging.debug('validate_signature inner _do')
            request = args[0]

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

            # FIXME signature may be in the auth header
            if not 'oauth_signature' in request.REQUEST:
                return HttpResponse('no signature')
            if self.sig_method.check_signature(oauth_request, self.consumer, None, request.REQUEST['oauth_signature']):
                return view(*args, **kwargs)
            else:
                return HttpResponse('failed auth check')
        return _do

    def require_access_token(self, view):
        """
        A decorator for Django views that require an Access Token. It will make
        the access token available as request.{NAME}_access_token where NAME
        was defined in the instance configuration. If an Access Token is not
        available, it will render a templated called:
            "django_oauth_consumer/{NAME}/need_authorization.html"

        """
        def _do(*args, **kwargs):
            request = args[0]
            logging.info('require_access_token inner _do')
            try:
                access_token = OAuthUserToken.objects.get(service_provider=self.name, user=request.user, type=OAuthUserToken.ACCESS_TOKEN)
                setattr(request, self.name + '_access_token', oauth.OAuthToken(access_token.key, access_token.secret))
                return view(*args, **kwargs)
            except OAuthUserToken.DoesNotExist:
                response = self.make_signed_req(self.request_token_url)
                request_token = oauth.OAuthToken.from_string(unicode(response.read(), 'utf8').strip())
                OAuthUserToken.objects.create(
                        service_provider=self.name,
                        user=request.user,
                        type=OAuthUserToken.REQUEST_TOKEN,
                        key=request_token.key,
                        secret=request_token.secret)
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
                return render('django_oauth_consumer/' + self.name + '/need_authorization.html', {'authorization_url': url})
        return _do

    def success_auth(self, request, oauth_token=None):
        """
        A Django view to handle a successful OAuth Authorization flow from the
        user's side. The Service Provider redirect returns the user here.

        """
        request_token_record = OAuthUserToken.objects.get(service_provider=self.name, type=OAuthUserToken.REQUEST_TOKEN, key=oauth_token)
        request_token = oauth.OAuthToken(request_token_record.key, request_token_record.secret)
        response = self.make_signed_req(self.access_token_url, token=request_token)
        body = unicode(response.read(), 'utf8').strip()
        access_token = oauth.OAuthToken.from_string(body)
        OAuthUserToken.objects.create(
                service_provider=self.name,
                user=request_token_record.user,
                type=OAuthUserToken.ACCESS_TOKEN,
                key=access_token.key,
                secret=access_token.secret)
        request_token_record.delete()
        return HttpResponse('success!')
