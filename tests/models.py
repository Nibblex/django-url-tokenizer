from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.password_validation import validate_password
from django.db import models
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError

from urltokenizer.mixins import URLTokenizerMixin


class BaseProfile(AbstractBaseUser, PermissionsMixin, URLTokenizerMixin):
    email = models.EmailField(max_length=255, unique=True)

    USERNAME_FIELD = "email"  # AbstractBaseUser

    class Meta:
        abstract = True

    def _set_password(
        self, password: str, password2: str, raise_exception: bool = False
    ) -> ValidationError | None:
        exc = None

        if password == password2:
            try:
                validate_password(password, user=self)
            except ValidationError as e:
                exc = e
        else:
            exc = ValidationError(_("passwords don't match"))

        if exc:
            if raise_exception:
                raise exc
            return exc

        super().set_password(password)
        self.save()
