import types, urllib, httplib, oauth
from urlparse import urlparse
from cgi import parse_qs
import logging as log
from django.conf.urls.defaults import patterns, url
from django.http import HttpResponse
from django.shortcuts import render_to_response as render
from django.core.urlresolvers import reverse
from django_oauth.models import OAuthUserToken

# use to provide access_token for require_access_token decoration

def make_app(config):
    """
    Makes a app module that contains helpers, views and urls for a django_oauth
    bound to the given config.

    """

    NAME = config['name']

    CONSUMER_KEY = config['consumer_key']
    CONSUMER_SECRET = config['consumer_secret']

    REQUEST_TOKEN_URL = config.get('request_token_url', None)
    AUTHORIZATION_URL = config.get('authorization_url', None)
    ACCESS_TOKEN_URL = config.get('access_token_url', None)

    CONSUMER = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
    SIG_METHOD = oauth.OAuthSignatureMethod_HMAC_SHA1()

    def make_signed_req(url, method='GET', parameters={}, token=None):
        """
        The url is broken down and query parameters are extracted. These are merged
        with the optional parameters argument. Values in the parameters argument
        take precedence.

        Finally the data is sent via the POST body or the Query String along with
        the OAuth Authorization header.

        """

        parts = urlparse(url)
        if parts.scheme == 'https':
            log.debug('Using HTTPSConnection')
            connection = httplib.HTTPSConnection(parts.netloc)
        else:
            log.debug('Using HTTPSConnection')
            connection = httplib.HTTPConnection(parts.netloc)

        # drop the query string and use it if it exists
        url = parts.scheme + '://' + parts.netloc + parts.path
        if parts.query != '':
            qs_params = dict([(k, v[0]) for k, v in parse_qs(parts.query).iteritems()])
            qs_params.update(parameters)
            parameters = qs_params

        request = oauth.OAuthRequest.from_consumer_and_token(
                CONSUMER,
                token=token,
                http_method=method,
                http_url=url,
                parameters=parameters)
        request.sign_request(SIG_METHOD, CONSUMER, token)

        method = request.get_normalized_http_method()
        headers = request.to_header()
        url = request.get_normalized_http_url()
        data = '&'.join('%s=%s' % (oauth.escape(str(k)), oauth.escape(str(v))) for k, v in request.get_nonoauth_parameters().iteritems())
        body = None

        if data and data != '':
            if request.get_normalized_http_method() == 'POST':
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                body = data
            else:
                url = url + '?' + data

        log.debug('Method: ' + str(method))
        log.debug('Url: ' + str(url))
        log.debug('Body: ' + str(body))
        log.debug('Headers: ' + str(headers))

        connection.request(method, url, body, headers)
        return connection.getresponse()

    def validate_signature(view):
        def _do(*args, **kwargs):
            log.debug('validate_signature inner _do')
            request = args[0]

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
            if SIG_METHOD.check_signature(oauth_request, CONSUMER, None, request.REQUEST['oauth_signature']):
                return view(*args, **kwargs)
            else:
                return HttpResponse('failed auth check')
        return _do

    def success(request):
        request_token_record = OAuthUserToken.objects.get(type=OAuthUserToken.REQUEST_TOKEN, key=request.REQUEST['oauth_token'])
        request_token = oauth.OAuthToken(request_token_record.key, request_token_record.secret)
        response = make_signed_req(ACCESS_TOKEN_URL, token=request_token)
        body = unicode(response.read(), 'utf8').strip()
        access_token = oauth.OAuthToken.from_string(body)
        OAuthUserToken.objects.create(
                user=request_token_record.user,
                type=OAuthUserToken.ACCESS_TOKEN,
                key=access_token.key,
                secret=access_token.secret)
        request_token_record.delete()
        return HttpResponse('success!')

    def require_access_token(view):
        def _do(*args, **kwargs):
            request = args[0]
            log.info('require_access_token inner _do')
            try:
                access_token = OAuthUserToken.objects.get(user=request.user, type=OAuthUserToken.ACCESS_TOKEN)
                setattr(request, NAME + '_access_token', oauth.OAuthToken(access_token.key, access_token.secret))
                return view(*args, **kwargs)
            except OAuthUserToken.DoesNotExist:
                response = make_signed_req(REQUEST_TOKEN_URL)
                request_token = oauth.OAuthToken.from_string(unicode(response.read(), 'utf8').strip())
                OAuthUserToken.objects.create(
                        user=request.user,
                        type=OAuthUserToken.REQUEST_TOKEN,
                        key=request_token.key,
                        secret=request_token.secret)
                qs = urllib.urlencode({
                    'oauth_token': request_token.key,
                    'oauth_callback': request.build_absolute_uri(reverse(NAME + '_success')),
                })
                url = AUTHORIZATION_URL
                if '?' in url:
                    if url[-1] == '&':
                        url += qs
                    else:
                        url += '&' + qs
                else:
                    url += '?' + qs
                return render('django_oauth/need_authorization.html', {'authorization_url': url})
        return _do

    # dynamic module
    views = types.ModuleType('views')
    views.success = success

    app = types.ModuleType(NAME + '_oauth')
    app.views = views
    app.make_signed_req = make_signed_req
    app.validate_signature = validate_signature
    app.require_access_token = require_access_token
    return app
