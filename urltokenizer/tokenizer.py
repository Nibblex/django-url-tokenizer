import hashlib
import threading
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.db.utils import ProgrammingError
from django.utils import timezone
from django.utils.encoding import DjangoUnicodeDecodeError, force_bytes
from django.utils.translation import gettext_lazy as _

from .enums import Channel
from .exceptions import ErrorCode, URLTokenizerError
from .models import Log
from .token_generator import TokenGenerator
from .utils import SETTINGS, decode, encode, from_config, str_import

try:
    from sms import send_sms

    HAS_SMS = True
except ImportError:
    HAS_SMS = False


@dataclass
class URLToken:
    user: object
    type: str
    created_at: datetime = timezone.now()
    uidb64: str = ""
    token: str = ""
    link: str = ""
    hash: str | None = None
    email: str = ""
    name: str = ""
    phone: str = ""
    channel: Channel | None = None
    precondition_failed: bool = False
    sent: bool = False
    exception: URLTokenizerError | None = None
    log: Log | None = None

    def _(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

        return self

    def _log(self) -> Log | None:
        with suppress(ProgrammingError):
            self.log = Log.objects.create(
                created_at=self.created_at,
                token_type=self.type,
                uidb64=self.uidb64,
                hash=self.hash,
                email=self.email,
                name=self.name,
                phone=self.phone,
                channel=self.channel,
                precondition_failed=self.precondition_failed,
                sent=self.sent,
                errors=self.exception.__repr__() if self.exception else None,
                user=self.user,
            )

            return self.log

        return None


class URLTokenizer:
    @property
    def user_model(self) -> object:
        return get_user_model()

    @property
    def encoding_field(self) -> str:
        return self._token_generator.encoding_field

    def __init__(self, token_type: str | Enum | None = None):
        self.token_type = self._parse_token_type(token_type)
        # at this point token_type is either None or a string

        token_config = self._get_token_config(SETTINGS, self.token_type)
        self._token_generator = TokenGenerator(token_config)

        # token
        self.validate_token_type = SETTINGS.get("VALIDATE_TOKEN_TYPE", True)
        self.fail_silently = from_config(token_config, "fail_silently", False)

        # logging
        self.logging_enabled = from_config(token_config, "logging_enabled", False)

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
            token_config,
            "email_subject",
            "link generated with django-url-tokenizer",
        )

        # sms
        self.phone_field = from_config(token_config, "phone_field", "phone")

    # initialization

    @staticmethod
    def _parse_token_type(token_type: str | Enum | None) -> str | None:
        if isinstance(token_type, str):
            token_type = token_type.strip().lower()
        elif isinstance(token_type, Enum):
            token_type = token_type.value.strip().lower()
        elif token_type is not None:
            raise ValueError(_("'token_type' must be either a string or Enum"))

        return token_type

    def _get_token_config(
        self, settings_: dict[str, Any], token_type: str | None
    ) -> dict[str, Any]:
        TOKEN_CONFIG = settings_.get("TOKEN_CONFIG", {})

        # avoid empty token_type
        if any(key.strip() == "" for key in TOKEN_CONFIG.keys()):
            raise ImproperlyConfigured(
                _("TOKEN_CONFIG cannot contain blank 'token_type'.")
            )

        if token_type is None:
            return TOKEN_CONFIG.get("default", {})

        # validate token_type
        token_config = TOKEN_CONFIG.get(token_type, None)
        if token_config is None and self.validate_token_type:
            raise URLTokenizerError(ErrorCode.invalid_token_type, token_type=token_type)

        return token_config or TOKEN_CONFIG.get("default", {})

    # helpers

    def _validate_preconditions(
        self, url_token: URLToken, fail_silently: bool = False
    ) -> bool:
        for pred in self.send_preconditions:
            try:
                if pred(url_token.user):
                    continue

            except Exception as e:
                url_token.exception = URLTokenizerError(
                    ErrorCode.send_precondition_execution_error,
                    context={"exception": e},
                    pred=pred,
                )

            url_token.precondition_failed = url_token.exception is None
            if self.logging_enabled:
                url_token._log()

            if url_token.exception and not fail_silently:
                from_exc = url_token.exception.context.get("exception")
                raise url_token.exception from from_exc

            return False

        return True

    # main methods

    def generate_tokenized_link(
        self,
        user: object,
        path: str | None = None,
        domain: str | None = None,
        protocol: str | None = None,
        port: str | None = None,
        channel: Channel | None = None,
        email_subject: str | None = None,
        fail_silently: bool | None = None,
    ) -> URLToken:
        path = path or self.path
        domain = domain or self.domain
        protocol = protocol or self.protocol
        port = port or self.port
        channel = channel or self.channel
        email_subject = email_subject or self.email_subject

        if fail_silently is None:
            fail_silently = self.fail_silently

        email = str(getattr(user, self.email_field, "") or "")
        name = str(getattr(user, self.name_field, "") or "")
        phone = str(getattr(user, self.phone_field, "") or "")
        url_token = URLToken(
            user, self.token_type, email=email, name=name, phone=phone, channel=channel
        )

        if not self._validate_preconditions(url_token, fail_silently):
            return url_token

        uidb64 = encode(getattr(user, self.encoding_field))
        token = self._token_generator.make_token(user)
        link = f"{protocol}://{domain}:{port}/{self.path}?uid={uidb64}&key={token}"
        hash = hashlib.sha256(force_bytes(uidb64 + token)).hexdigest()

        sent, exc = 0, None
        if self.send_enabled:
            if channel == Channel.EMAIL:
                if email:
                    sent = send_mail(
                        subject=email_subject,
                        message=link,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[email],
                        fail_silently=fail_silently,
                    )

                else:
                    exc = URLTokenizerError(ErrorCode.no_email)

            elif channel == Channel.SMS and HAS_SMS:
                if phone:
                    sent = send_sms(
                        body=link,
                        originator=settings.DEFAULT_FROM_SMS,
                        recipients=[phone],
                        fail_silently=fail_silently,
                    )

                else:
                    exc = URLTokenizerError(ErrorCode.no_phone)

        url_token = url_token._(
            uidb64=uidb64, token=token, link=link, hash=hash, sent=sent > 0, exception=exc
        )

        if self.logging_enabled:
            url_token._log()

        if exc and not fail_silently:
            raise exc

        return url_token

    def bulk_generate_tokenized_link(
        self,
        users: Iterable[object],
        path: str | None = None,
        domain: str | None = None,
        protocol: str | None = None,
        port: str | None = None,
        channel: Channel | None = None,
        email_subject: str | None = None,
        fail_silently: bool | None = None,
    ) -> list[URLToken]:
        if fail_silently is None:
            fail_silently = self.fail_silently

        url_tokens, threads = [], []

        # Define a helper function to execute generate_tokenized_link for each user
        def generate_link(user):
            url_token = self.generate_tokenized_link(
                user,
                path=path,
                domain=domain,
                protocol=protocol,
                port=port,
                channel=channel,
                email_subject=email_subject,
                fail_silently=fail_silently,
            )
            url_tokens.append(url_token)

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

    def check_token(
        self,
        uidb64: str,
        token: str,
        user_data: dict[str, Any] | None = None,
        fail_silently: bool | None = None,
    ) -> tuple[object | None, Log | None]:
        if fail_silently is None:
            fail_silently = self.fail_silently

        # decode uidb64
        try:
            decoded_attr = decode(uidb64)
        except DjangoUnicodeDecodeError:
            return None, None

        # user lookup
        user = self.user_model.objects.filter(
            **{self.encoding_field: decoded_attr}
        ).first()
        if not user:
            return None, None

        # check token
        checked, log = self._token_generator.check_token(
            user, token, user_data=user_data, fail_silently=fail_silently
        )
        if not checked:
            return None, None

        return user, log

    def run_callbacks(
        self,
        user: object,
        callback_kwargs: Iterable[dict[str, Any]] | None = None,
        fail_silently: bool | None = None,
    ) -> dict[str, list[Any]]:
        if fail_silently is None:
            fail_silently = self.fail_silently

        callbacks_returns = self._token_generator.run_callbacks(
            user, callback_kwargs=callback_kwargs, fail_silently=fail_silently
        )

        return callbacks_returns


default_tokenizer = URLTokenizer()
