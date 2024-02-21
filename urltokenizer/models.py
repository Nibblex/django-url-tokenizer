from django.conf import settings
from django.db import models
from django.utils import timezone

from .enums import Channel


class Log(models.Model):
    created_at = models.DateTimeField(null=True)
    checked_at = models.DateTimeField(null=True)
    expires_at = models.DateTimeField(null=True)
    token_type = models.CharField(max_length=255, null=True)
    uidb64 = models.CharField(max_length=255, null=True)
    hash = models.CharField(max_length=255, unique=True, null=True)
    name = models.CharField(max_length=255, null=True)
    email = models.EmailField(null=True)
    phone = models.CharField(max_length=255, null=True)
    channel = models.CharField(max_length=255, choices=Channel.choices, null=True)
    send_precondition_failed = models.BooleanField(default=False)
    check_precondition_failed = models.BooleanField(default=False)
    sent = models.BooleanField(default=False)
    errors = models.CharField(max_length=255, null=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True
    )

    @property
    def checked(self) -> bool:
        return self.checked_at is not None

    def _check(self):
        if not self.checked:
            self.checked_at = timezone.now()
            self.save(update_fields=["checked_at"])
