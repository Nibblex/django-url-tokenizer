from enum import Enum
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _

from rest_framework.exceptions import ValidationError


class TokenGenerator(PasswordResetTokenGenerator):
    def __init__(self, token_config):
        self.token_config = token_config
        super().__init__()

    def _make_hash_value(self, user, timestamp):
        attributes = [
            getattr(user, attribute)
            for attribute in self.token_config.get("attributes", [])
        ]
        return f"{user.pk}{timestamp}{attributes}"

    def check_token(self, user, token):
        permissions = self.token_config["permissions"].items()
        all(getattr(user, attribute) == value for attribute, value in permissions)
        return super().check_token(user, token)

    def run_callbacks(self, user, **kwargs):
        callbacks = self.token_config.get("callbacks", [])
        for callback in callbacks:
            method = getattr(user, callback.get("method"), None)
            if method is None:
                continue

            kwargs = {
                key: value
                for key, value in kwargs.items()
                if key in callback.get("kwargs", [])
            }
            kwargs.update(callback.get("defaults", {}))

            try:
                method(**kwargs)
            except Exception as e:
                raise ValidationError(_("failed to execute callback")) from e


class Tokenizer:
    def __init__(self, token_type: str | Enum):
        SETTINGS = getattr(settings, "URLTOKENIZER_SETTINGS", None)
        if not SETTINGS:
            raise ValidationError(
                _("URLTOKENIZER_SETTINGS must be defined in settings.py")
            )

        self.token_type = (
            token_type.value if isinstance(token_type, Enum) else token_type
        )
        self._settings = SETTINGS
        self._token_generator = self._get_token_generator(self.token_type, SETTINGS)

    @staticmethod
    def _get_token_generator(token_type: str, SETTINGS: dict) -> TokenGenerator:
        token_config = SETTINGS.get("TOKEN_CONFIG", {}).get(token_type, {})
        return TokenGenerator(token_config)

    @property
    def token_config(self) -> dict:
        return self._token_generator.token_config

    @property
    def user_model(self):
        return get_user_model()

    @property
    def encoding_field(self) -> str:
        return self.user_model.ENCODING_FIELD

    @staticmethod
    def encode(s: Any) -> str:
        return urlsafe_base64_encode(force_bytes(s))

    @staticmethod
    def decode(s: bytes | str) -> str:
        return force_str(urlsafe_base64_decode(s))

    @property
    def default_domain(self) -> str:
        return self._settings.get("DEFAULT_DOMAIN", "")

    def generate_tokenized_link(
        self, user, domain: str = None, send_email: bool = False
    ) -> tuple[str, str, str, bool]:
        uidb64 = self.encode(getattr(user, user.ENCODING_FIELD))
        token = self._token_generator.make_token(user)

        domain = domain or self.token_config.get("domain", self.default_domain)
        link = f"http://www.{domain}/{self.token_type}?uid={uidb64}&key={token}"

        email_sent = 0
        email_config = self.token_config.get("email", {})
        if send_email and email_config.get("enabled", False):
            email_sent = send_mail(
                subject=email_config.get("subject", ""),
                message=link,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[getattr(user, user.EMAIL_FIELD, None)],
                fail_silently=True,
            )

        return uidb64, token, link, email_sent > 0

    def check_token(self, uidb64: str, token: str, **kwargs):
        try:
            encoding_attr = self.decode(uidb64)
        except DjangoUnicodeDecodeError:
            return None

        user = self.user_model.objects.filter(
            **{self.encoding_field: encoding_attr}
        ).first()
        if not user:
            return None

        if not self._token_generator.check_token(user, token):
            return None

        self._token_generator.run_callbacks(user, **kwargs)

        return user
