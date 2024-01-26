from django.db import models

from .enums import Channel


class Log(models.Model):
    token_type = models.CharField(max_length=255, null=True)
    timestamp = models.DateTimeField(null=True)
    uidb64 = models.CharField(max_length=255, null=True)
    hash = models.CharField(max_length=255, null=True)
    email = models.EmailField(null=True)
    name = models.CharField(max_length=255, null=True)
    phone = models.CharField(max_length=255, null=True)
    channel = models.CharField(max_length=255, choices=Channel.choices, null=True)
    precondition_failed = models.BooleanField(default=False)
    sent = models.BooleanField(default=False)
    # errors = models.JSONField(default=dict)
