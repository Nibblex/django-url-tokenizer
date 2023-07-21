import threading
from collections import namedtuple
from enum import Enum
from typing import Any, Iterable, Optional, Union

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _

from .exceptions import InvalidTokenTypeError
from .token_generator import TokenGenerator

SETTINGS = getattr(settings, "URL_TOKENIZER_SETTINGS", {})


def _get_or_else(config: dict, key: str, default: Any) -> Any:
    return config.get(key, SETTINGS.get(key.upper(), default))


class URLTokenizer:
    def __init__(self, token_type: Optional[Union[str, Enum]] = None):
        self.token_type = self._parse_token_type(token_type)
        # at this point token_type is either None or a string

        token_config = self._get_token_config(SETTINGS, self.token_type)
        self._token_generator = self._get_token_generator(token_config)

        # token
        self.encoding_field = _get_or_else(token_config, "encoding_field", "pk")
        self.fail_silently = _get_or_else(token_config, "fail_silently", False)

        # url
        self.path = _get_or_else(token_config, "path", "").strip("/")
        self.domain = _get_or_else(token_config, "domain", "localhost")
        self.protocol = _get_or_else(token_config, "protocol", "http")
        self.port = _get_or_else(token_config, "port", "80")

        # email
        self.email_enabled = _get_or_else(token_config, "email_enabled", False)
        self.email_field = _get_or_else(token_config, "email_field", "email")
        self.email_subject = _get_or_else(
            token_config, "email_subject", "link generated with django-url-tokenizer"
        )

    @staticmethod
    def _parse_token_type(token_type: Optional[Union[str, Enum]]) -> Optional[str]:
        if isinstance(token_type, str):
            token_type = token_type.strip().lower()
        elif isinstance(token_type, Enum):
            token_type = token_type.value.strip().lower()
        elif token_type is not None:
            raise ValueError(_("token_type must be either a string or Enum"))

        return token_type

    @staticmethod
    def _get_token_config(settings_: dict, token_type: Optional[str]) -> dict:
        TOKEN_CONFIG = settings_.get("TOKEN_CONFIG", {})

        # avoid empty token_type
        if any((x.strip() == "" for x in TOKEN_CONFIG.keys())):
            raise ImproperlyConfigured(
                _("TOKEN_CONFIG cannot contain blank token_type.")
            )

        if token_type is None:
            return TOKEN_CONFIG.get("default", {})

        token_config = TOKEN_CONFIG.get(token_type, None)
        validate_token_type = settings_.get("VALIDATE_TOKEN_TYPE", True)

        if token_config is None and validate_token_type:
            raise InvalidTokenTypeError(_(f"invalid token type: {token_type}"))

        return token_config or TOKEN_CONFIG.get("default", {})

    @staticmethod
    def _get_token_generator(token_config: dict) -> TokenGenerator:
        return TokenGenerator(
            attributes=_get_or_else(token_config, "attributes", []),
            preconditions=_get_or_else(token_config, "preconditions", {}),
            callbacks=_get_or_else(token_config, "callbacks", []),
            timeout=_get_or_else(token_config, "timeout", 60),
        )

    @property
    def user_model(self):
        return get_user_model()

    # encoding

    @staticmethod
    def encode(s: Any) -> str:
        return urlsafe_base64_encode(force_bytes(s))

    @staticmethod
    def decode(s: Union[bytes, str]) -> str:
        return force_str(urlsafe_base64_decode(s))

    # main methods

    def generate_tokenized_link(
        self,
        user,
        path: Optional[str] = None,
        domain: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[str] = None,
        email_subject: Optional[str] = None,
        send_email: bool = False,
    ):
        path = path or self.path
        domain = domain or self.domain
        protocol = protocol or self.protocol
        port = port or self.port
        email_subject = email_subject or self.email_subject

        uidb64 = self.encode(getattr(user, self.encoding_field))
        token = self._token_generator.make_token(user)

        link = f"{protocol}://{domain}:{port}/{self.path}?uid={uidb64}&key={token}"

        email_sent, email = False, getattr(user, self.email_field)
        if send_email and self.email_enabled:
            email_sent = send_mail(
                subject=email_subject,
                message=link,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=True,
            )

        named_tuple = namedtuple(
            "URLToken", ["user", "uidb64", "token", "link", "email_sent"]
        )

        return named_tuple(user, uidb64, token, link, email_sent > 0)

    def bulk_generate_tokenized_link(
        self,
        users: Iterable,
        path: Optional[str] = None,
        domain: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[str] = None,
        email_subject: Optional[str] = None,
        send_email: bool = False,
    ):
        result = []
        threads = []

        # Define a helper function to execute generate_tokenized_link for each user
        def generate_link(user):
            named_tuple = self.generate_tokenized_link(
                user, path, domain, protocol, port, email_subject, send_email
            )
            result.append(named_tuple)

        # Create a thread for each user
        for user in users:
            thread = threading.Thread(target=generate_link, args=(user,))
            threads.append(thread)

        # Start all the threads
        for thread in threads:
            thread.start()

        # Wait for all the threads to finish
        for thread in threads:
            thread.join()

        return result

    def check_token(self, uidb64: str, token: str):
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

        return user

    def run_callbacks(
        self,
        user,
        callback_kwargs: Iterable[dict] = [],
        fail_silently: Optional[bool] = None,
    ):
        if fail_silently is None:
            fail_silently = self.fail_silently

        callbacks_returns = self._token_generator.run_callbacks(
            user, callback_kwargs=callback_kwargs, fail_silently=fail_silently
        )

        return callbacks_returns


default_tokenizer = URLTokenizer()
