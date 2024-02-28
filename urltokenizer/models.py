from django.conf import settings
from django.db import models
from django.utils import timezone

from .enums import Channel


class Log(models.Model):
    created_at = models.DateTimeField(null=True, editable=False)
    checked_at = models.DateTimeField(null=True, editable=False)
    expires_at = models.DateTimeField(null=True, editable=False)
    token_type = models.CharField(max_length=255, null=True, editable=False)
    uidb64 = models.CharField(max_length=255, null=True, editable=False)
    hash = models.CharField(max_length=255, unique=True, null=True, editable=False)
    name = models.CharField(max_length=255, null=True, editable=False)
    email = models.EmailField(null=True, editable=False)
    phone = models.CharField(max_length=255, null=True, editable=False)
    channel = models.CharField(
        max_length=255, choices=Channel.choices, null=True, editable=False
    )
    send_precondition_failed = models.CharField(max_length=255, null=True, editable=False)
    check_precondition_failed = models.CharField(
        max_length=255, null=True, editable=False
    )
    sent = models.BooleanField(default=False, editable=False)
    errors = models.CharField(max_length=255, null=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, editable=False
    )

    @property
    def checked(self) -> bool:
        return self.checked_at is not None

    def _check(self):
        if not self.checked:
            self.checked_at = timezone.now()
            self.save(update_fields=["checked_at"])
