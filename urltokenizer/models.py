from django.contrib.auth import get_user_model
from django.db import models

from .enums import Channel

User = get_user_model()


class Log(models.Model):
    created_at = models.DateTimeField(null=True)
    checked_at = models.DateTimeField(null=True)
    token_type = models.CharField(max_length=255, null=True)
    uidb64 = models.CharField(max_length=255, null=True)
    hash = models.CharField(max_length=255, unique=True, null=True)
    name = models.CharField(max_length=255, null=True)
    email = models.EmailField(null=True)
    phone = models.CharField(max_length=255, null=True)
    channel = models.CharField(max_length=255, choices=Channel.choices, null=True)
    precondition_failed = models.BooleanField(default=False)
    sent = models.BooleanField(default=False)
    errors = models.CharField(max_length=255, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)

    @property
    def checked(self):
        return self.checked_at is not None
