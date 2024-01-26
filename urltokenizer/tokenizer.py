import hashlib
import threading
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Iterable

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.db.utils import ProgrammingError
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _

from .enums import Channel
from .exceptions import URLTokenizerError, ErrorCodes
from .models import Log
from .token_generator import TokenGenerator
from .utils import str_import

SETTINGS = getattr(settings, "URL_TOKENIZER_SETTINGS", {})

try:
    from sms import send_sms

    HAS_SMS = True
except ImportError:
    HAS_SMS = False


def from_config(config: dict, key: str, default: Any) -> Any:
    return config.get(key, SETTINGS.get(key.upper(), default))


@dataclass
class URLToken:
    type: str | None
    user: object
    email: str
    name: str
    phone: str = ""
    uidb64: str = ""
    token: str = ""
    link: str = ""
    hash: str = ""
    timestamp: datetime = timezone.now()
    precondition_failed: bool = False
    channel: Channel | None = None
    sent: bool = False
    exception: URLTokenizerError | None = None

    def _replace(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

        return self


def create_log(url_token: URLToken) -> Log:
    return Log.objects.create(
        token_type=url_token.type,
        timestamp=url_token.timestamp,
        uidb64=url_token.uidb64,
        hash=url_token.hash,
        email=url_token.email,
        name=url_token.name,
        phone=url_token.phone,
        channel=url_token.channel,
        precondition_failed=url_token.precondition_failed,
        sent=url_token.sent,
    )


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

        # sending
        self.send_enabled = from_config(token_config, "send_enabled", False)
        self.channel = from_config(token_config, "channel", None)
        self.send_preconditions = str_import(
            SETTINGS.get("SEND_PRECONDITIONS", [])
            + token_config.get("send_preconditions", [])
        )

        # email
        self.email_field = from_config(token_config, "email_field", "email")
        self.name_field = from_config(token_config, "name_field", "name")
        self.email_subject = from_config(
            token_config, "email_subject", "link generated with django-url-tokenizer"
        )

        # sms
        self.phone_field = from_config(token_config, "phone_field", "phone")

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
        channel: Channel | None = None,
        email_subject: str | None = None,
        fail_silently: bool | None = None,
    ):
        path = path or self.path
        domain = domain or self.domain
        protocol = protocol or self.protocol
        port = port or self.port
        channel = channel or self.channel
        email_subject = email_subject or self.email_subject

        if fail_silently is None:
            fail_silently = self.fail_silently

        email = str(getattr(user, self.email_field))
        name = str(getattr(user, self.name_field, ""))
        phone = str(getattr(user, self.phone_field, "") or "")
        url_token = URLToken(self.token_type, user, email, name, phone, channel=channel)

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
        url_token.hash = hashlib.sha256(force_bytes(uidb64 + token)).hexdigest()
        link = f"{protocol}://{domain}:{port}/{self.path}?uid={uidb64}&key={token}"
        if channel:
            link += f"&channel={channel}"

        sent = 0
        if self.send_enabled:
            if channel == Channel.EMAIL:
                sent = send_mail(
                    subject=email_subject,
                    message=link,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=fail_silently,
                )
            elif channel == Channel.SMS and HAS_SMS:
                sent = send_sms(
                    body=link,
                    originator=settings.DEFAULT_FROM_SMS,
                    recipients=[phone],
                    fail_silently=fail_silently,
                )

        url_token = url_token._replace(
            uidb64=uidb64, token=token, link=link, sent=sent > 0
        )
        with suppress(ProgrammingError):
            create_log(url_token)

        return url_token

    def bulk_generate_tokenized_link(
        self,
        users: Iterable,
        path: str | None = None,
        domain: str | None = None,
        protocol: str | None = None,
        port: str | None = None,
        channel: Channel | None = None,
        email_subject: str | None = None,
        fail_silently: bool | None = None,
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
                channel=channel,
                email_subject=email_subject,
                fail_silently=fail_silently,
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
