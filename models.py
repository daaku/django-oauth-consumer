from django.db import models
from django.contrib.auth.models import User


class OAuthUserToken(models.Model):
    REQUEST_TOKEN = 1
    ACCESS_TOKEN = 2
    TOKEN_TYPES = (
        (REQUEST_TOKEN, 'Request Token'),
        (ACCESS_TOKEN, 'Access Token'),
    )
    user = models.ForeignKey(User)
    service_provider = models.CharField(max_length=256)
    type = models.IntegerField(choices=TOKEN_TYPES, default=REQUEST_TOKEN)
    key = models.CharField(max_length=256, blank=True, null=True)
    secret = models.CharField(max_length=256, blank=True, null=True)
