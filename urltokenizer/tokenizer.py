from enum import Enum
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _

from .token_generator import TokenGenerator

SETTINGS = getattr(settings, "URLTOKENIZER_SETTINGS", {})


def _get_or_else(config: dict, key: str, default: Any) -> Any:
    return config.get(key, SETTINGS.get(key.upper(), default))


class Tokenizer:
    def __init__(self, token_type: str | Enum | None = None):
        if isinstance(token_type, Enum):
            token_type = token_type.value.strip().lower()
        elif isinstance(token_type, str):
            token_type = token_type.strip().lower()
        elif token_type is not None:
            raise ValueError(_("token_type must be either a string or Enum"))

        # at this point token_type is either None or a string

        token_config = self._get_token_config(SETTINGS, token_type)
        self._token_generator = TokenGenerator(
            attributes=_get_or_else(token_config, "attributes", []),
            preconditions=_get_or_else(token_config, "preconditions", []),
            callbacks=_get_or_else(token_config, "callbacks", []),
            timeout=_get_or_else(token_config, "timeout", 60),
        )

        # token
        self.encoding_field = _get_or_else(token_config, "encoding_field", "pk")
        self.fail_silently = _get_or_else(token_config, "fail_silently", False)

        # url
        self.protocol = _get_or_else(token_config, "protocol", "http")
        self.port = _get_or_else(token_config, "port", "80")
        self.domain = _get_or_else(token_config, "domain", "localhost")

        # email
        self.email_enabled = _get_or_else(token_config, "email_enabled", False)
        self.email_field = _get_or_else(token_config, "email_field", "email")
        self.email_subject = _get_or_else(
            token_config, "email_subject", "link generated with django-url-tokenizer"
        )

    @staticmethod
    def _get_token_config(settings_: dict, token_type: str | None) -> dict:
        if token_type is None:
            return {}

        TOKEN_CONFIG = settings_.get("TOKEN_CONFIG", {})

        # avoid empty token_type
        if any((x.strip() == "" for x in TOKEN_CONFIG.keys())):
            raise ImproperlyConfigured(
                _("TOKEN_CONFIG cannot contain blank token_type.")
            )

        token_config = TOKEN_CONFIG.get(token_type, None)
        validate_token_type = settings_.get("VALIDATE_TOKEN_TYPE", True)

        if token_config is None and validate_token_type:
            raise ValidationError(_(f"invalid token type: {token_type}"))
        elif token_config is None and not validate_token_type:
            token_config = TOKEN_CONFIG.get("default", {})

        return token_config

    @property
    def user_model(self):
        return get_user_model()

    # encoding

    @staticmethod
    def encode(s: Any) -> str:
        return urlsafe_base64_encode(force_bytes(s))

    @staticmethod
    def decode(s: bytes | str) -> str:
        return force_str(urlsafe_base64_decode(s))

    # main methods

    def generate_tokenized_link(
        self,
        user,
        domain: str = None,
        protocol: str = None,
        port: str = None,
        send_email: bool = False,
    ) -> tuple[str, str, str, bool]:
        domain = domain or self.domain
        protocol = protocol or self.protocol
        port = port or self.port

        uidb64 = self.encode(getattr(user, self.encoding_field))
        token = self._token_generator.make_token(user)

        link = (
            f"{protocol}://{domain}:{port}/{self.token_type}?uid={uidb64}&key={token}"
        )

        email_sent = 0
        if send_email and self.email_enabled:
            email_sent = send_mail(
                subject=self.email_subject,
                message=link,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[getattr(user, self.email_field)],
                fail_silently=True,
            )

        return uidb64, token, link, email_sent > 0

    def check_token(
        self, uidb64: str, token: str, fail_silently: bool | None = None, **kwargs
    ):
        if fail_silently is None:
            fail_silently = self.fail_silently

        try:
            decoded_attr = self.decode(uidb64)
        except DjangoUnicodeDecodeError:
            return None

        user = self.user_model.objects.filter(
            **{self.encoding_field: decoded_attr}
        ).first()
        if not user:
            return None

        if not self._token_generator.check_token(user, token):
            return None

        try:
            self._token_generator.run_callbacks(user, **kwargs)
        except ValidationError as e:
            if not fail_silently:
                raise e
            return None

        return user


default_tokenizer = Tokenizer()
