import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _

from .exceptions import URLTokenizerError, ErrorCodes
from .token_generator import TokenGenerator
from .utils import str_import

SETTINGS = getattr(settings, "URL_TOKENIZER_SETTINGS", {})


def from_config(config: dict, key: str, default: Any) -> Any:
    return config.get(key, SETTINGS.get(key.upper(), default))


@dataclass
class URLToken:
    user: object
    email: str
    name: str
    uidb64: str = ""
    token: str = ""
    link: str = ""
    precondition_failed: bool = False
    email_sent: bool = False
    exception: URLTokenizerError | None = None

    def _replace(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

        return self


class URLTokenizer:
    def __init__(self, token_type: str | Enum | None = None):
        self.token_type = self._parse_token_type(token_type)
        # at this point token_type is either None or a string

        token_config = self._get_token_config(SETTINGS, self.token_type)
        self._token_generator = self._get_token_generator(token_config)

        # token
        self.encoding_field = from_config(token_config, "encoding_field", "pk")
        self.fail_silently = from_config(token_config, "fail_silently", False)

        # url
        self.path = from_config(token_config, "path", "").strip("/")
        self.domain = from_config(token_config, "domain", "localhost")
        self.protocol = from_config(token_config, "protocol", "http")
        self.port = from_config(token_config, "port", "80")

        # email
        self.email_enabled = from_config(token_config, "email_enabled", False)
        self.email_field = from_config(token_config, "email_field", "email")
        self.name_field = from_config(token_config, "name_field", "name")
        self.email_subject = from_config(
            token_config, "email_subject", "link generated with django-url-tokenizer"
        )
        self.send_preconditions = str_import(
            SETTINGS.get("SEND_PRECONDITIONS", [])
            + token_config.get("send_preconditions", [])
        )

    @staticmethod
    def _parse_token_type(token_type: str | Enum | None) -> str | None:
        if isinstance(token_type, str):
            token_type = token_type.strip().lower()
        elif isinstance(token_type, Enum):
            token_type = token_type.value.strip().lower()
        elif token_type is not None:
            raise ValueError(_("'token_type' must be either a string or Enum"))

        return token_type

    @staticmethod
    def _get_token_config(settings_: dict, token_type: str | None) -> dict:
        TOKEN_CONFIG = settings_.get("TOKEN_CONFIG", {})

        # avoid empty token_type
        if any((key.strip() == "" for key in TOKEN_CONFIG.keys())):
            raise ImproperlyConfigured(
                _("TOKEN_CONFIG cannot contain blank 'token_type'.")
            )

        if token_type is None:
            return TOKEN_CONFIG.get("default", {})

        token_config = TOKEN_CONFIG.get(token_type, None)
        validate_token_type = settings_.get("VALIDATE_TOKEN_TYPE", True)

        if token_config is None and validate_token_type:
            raise URLTokenizerError(
                ErrorCodes.invalid_token_type.value,
                ErrorCodes.invalid_token_type.name,
                token_type=token_type,
            )

        return token_config or TOKEN_CONFIG.get("default", {})

    @staticmethod
    def _get_token_generator(token_config: dict) -> TokenGenerator:
        check_preconditions = str_import(
            SETTINGS.get("CHECK_PRECONDITIONS", [])
            + token_config.get("check_preconditions", [])
        )

        return TokenGenerator(
            attributes=from_config(token_config, "attributes", []),
            check_preconditions=check_preconditions,
            callbacks=from_config(token_config, "callbacks", []),
            timeout=from_config(token_config, "timeout", 60),
        )

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
        path: str | None = None,
        domain: str | None = None,
        protocol: str | None = None,
        port: str | None = None,
        email_subject: str | None = None,
        fail_silently: bool | None = None,
        send_email: bool = False,
    ):
        path = path or self.path
        domain = domain or self.domain
        protocol = protocol or self.protocol
        port = port or self.port
        email_subject = email_subject or self.email_subject

        if fail_silently is None:
            fail_silently = self.fail_silently

        email = getattr(user, self.email_field)
        name = getattr(user, self.name_field, "")
        url_token = URLToken(user, email, name)

        for pred in self.send_preconditions:
            try:
                check = pred(user)
            except Exception as e:
                url_token.exception = URLTokenizerError(
                    ErrorCodes.send_precondition_execution_error.value,
                    ErrorCodes.send_precondition_execution_error.name,
                    context=dict(exception=e),
                    pred=pred,
                )

                if fail_silently:
                    return url_token

                raise url_token.exception from e

            if not check:
                return url_token._replace(precondition_failed=True)

        uidb64 = self.encode(getattr(user, self.encoding_field))
        token = self._token_generator.make_token(user)
        link = f"{protocol}://{domain}:{port}/{self.path}?uid={uidb64}&key={token}"

        email_sent = False
        if send_email and self.email_enabled:
            email_sent = send_mail(
                subject=email_subject,
                message=link,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=fail_silently,
            )

        return url_token._replace(
            uidb64=uidb64, token=token, link=link, email_sent=email_sent > 0
        )

    def bulk_generate_tokenized_link(
        self,
        users: Iterable,
        path: str | None = None,
        domain: str | None = None,
        protocol: str | None = None,
        port: str | None = None,
        email_subject: str | None = None,
        fail_silently: bool | None = None,
        send_email: bool = False,
    ):
        if fail_silently is None:
            fail_silently = self.fail_silently

        url_tokens, threads = [], []

        # Define a helper function to execute generate_tokenized_link for each user
        def generate_link(user):
            named_tuple = self.generate_tokenized_link(
                user,
                path=path,
                domain=domain,
                protocol=protocol,
                port=port,
                email_subject=email_subject,
                fail_silently=fail_silently,
                send_email=send_email,
            )
            url_tokens.append(named_tuple)

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

        return url_tokens

    def check_token(self, uidb64: str, token: str, fail_silently: bool | None = None):
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

        if not self._token_generator.check_token(
            user, token, fail_silently=fail_silently
        ):
            return None

        return user

    def run_callbacks(
        self,
        user,
        callback_kwargs: Iterable = [],
        fail_silently: bool | None = None,
    ):
        if fail_silently is None:
            fail_silently = self.fail_silently

        callbacks_returns = self._token_generator.run_callbacks(
            user, callback_kwargs=callback_kwargs, fail_silently=fail_silently
        )

        return callbacks_returns


default_tokenizer = URLTokenizer()
