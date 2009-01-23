from django.contrib import admin
from django_oauth_consumer.models import OAuthUserToken

admin.site.register(OAuthUserToken)
