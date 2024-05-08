import hashlib
import threading
from collections.abc import Iterable
from datetime import timedelta
from enum import Enum
from typing import Any, Callable

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.utils import timezone
from django.utils.encoding import DjangoUnicodeDecodeError, force_bytes
from django.utils.translation import gettext_lazy as _

from .enums import Channel
from .exceptions import ErrorCode, URLTokenizerError
from .models import Log
from .sendgrid.api import SendgridAPI
from .token_generator import TokenGenerator
from .utils import (
    SETTINGS,
    Template,
    URLToken,
    _from_config,
    _parse_preconditions,
    decode,
    encode,
    parse_path,
)

try:
    from sms import send_sms

    HAS_SMS = True
except ImportError:
    HAS_SMS = False


class URLTokenizer:
    @property
    def user_model(self) -> object:
        return get_user_model()

    @property
    def encoding_field(self) -> str:
        return self._token_generator.encoding_field

    def __init__(self, token_type: str | Enum | None = None):
        self.token_type = self._parse_token_type(token_type)
        self.validate_token_type = SETTINGS.get("VALIDATE_TOKEN_TYPE", True)
        # at this point token_type is either None or a string

        # token
        token_config = self._get_token_config(SETTINGS, self.token_type)
        self._token_generator = TokenGenerator(token_config)

        # url
        self.path = _from_config(token_config, "path", "")
        self.domain = _from_config(token_config, "domain", "localhost")
        self.protocol = _from_config(token_config, "protocol", "http")
        self.port = _from_config(token_config, "port", "80")

        # sending
        self.send_enabled = _from_config(token_config, "send_enabled", False)
        self.channel = _from_config(token_config, "channel", None)
        self.send_preconditions = _parse_preconditions(token_config, "send_preconditions")

        # template
        template_id = _from_config(token_config, "template_id", None)
        plain_content = _from_config(token_config, "plain_content", "")
        template_data = _from_config(token_config, "template_data", {})
        self.template = Template(template_id, plain_content, template_data)

        # email
        self.email_field = _from_config(token_config, "email_field", "email")
        self.name_field = _from_config(token_config, "name_field", "name")
        self.email_subject = _from_config(
            token_config,
            "email_subject",
            "link generated with django-url-tokenizer",
        )

        # sendgrid
        self._sendgrid_api = SendgridAPI(
            _from_config(token_config, "sender_name", None), settings.DEFAULT_FROM_EMAIL
        )

        # sms
        self.phone_field = _from_config(token_config, "phone_field", "phone")

        # logging
        self.logging_enabled = _from_config(token_config, "logging_enabled", False)

        # error handling
        self.fail_silently_on_generate = _from_config(
            token_config, "fail_silently_on_generate", False
        )
        self.fail_silently_on_bulk_generate = _from_config(
            token_config, "fail_silently_on_bulk_generate", False
        )
        self.fail_silently_on_check = _from_config(
            token_config, "fail_silently_on_check", False
        )
        self.fail_silently_on_callbacks = _from_config(
            token_config, "fail_silently_on_callbacks", False
        )

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
        for k, pred in self.send_preconditions.items():
            try:
                if pred(url_token.user):
                    continue
            except Exception as e:
                url_token.exception = URLTokenizerError(
                    ErrorCode.send_precondition_execution_error,
                    context={"exception": e},
                    pred=k,
                )

            url_token.precondition_failed = k

            if self.logging_enabled:
                url_token._log()

            if url_token.exception and not fail_silently:
                from_exc = url_token.exception.context.get("exception")
                raise url_token.exception from from_exc

            return False

        return True

    def _send_link(
        self,
        url_token: URLToken,
        template: Template | Callable[[URLToken], Template] | None = None,
        email_subject: str | None = None,
        fail_silently: bool = False,
    ) -> URLToken:
        if callable(template) and not isinstance(template, Template):
            template = template(url_token)

        message = template.render(url_token) if template else None

        if url_token.channel == Channel.EMAIL:
            if not url_token.email:
                return url_token._(exception=URLTokenizerError(ErrorCode.no_email))

            # sendgrid
            if template.id and self._sendgrid_api._client:
                personalizations = [
                    {
                        "to": [{"email": url_token.email, "name": url_token.name}],
                        "dynamic_template_data": template.get_template_data(url_token),
                    }
                ]

                sent = self._sendgrid_api.send_mail(
                    personalizations,
                    template_id=template.id,
                    fail_silently=fail_silently,
                )

            # django send_mail
            else:
                sent = send_mail(
                    subject=email_subject,
                    message=message or url_token.link,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[url_token.email],
                    fail_silently=fail_silently,
                )

            url_token.sent = sent > 0

        elif url_token.channel == Channel.SMS and HAS_SMS:
            if not url_token.phone:
                return url_token._(exception=URLTokenizerError(ErrorCode.no_phone))

            sent = send_sms(
                body=message or url_token.link,
                originator=settings.DEFAULT_FROM_SMS,
                recipients=[url_token.phone],
                fail_silently=fail_silently,
            )
            url_token.sent = sent > 0

        return url_token

    # main methods

    def generate_tokenized_link(
        self,
        user: object,
        path: str | Callable[[object], str] | None = None,
        domain: str | None = None,
        protocol: str | None = None,
        port: str | None = None,
        channel: Channel | None = None,
        template: Template | Callable[[URLToken], Template] | None = None,
        email_subject: str | None = None,
        fail_silently: bool | None = None,
    ) -> URLToken:
        path = parse_path(path or self.path)
        domain = domain or self.domain
        protocol = protocol or self.protocol
        port = port or self.port
        channel = channel or self.channel
        template = template or self.template
        email_subject = email_subject or self.email_subject
        if fail_silently is None:
            fail_silently = self.fail_silently_on_generate

        email = str(getattr(user, self.email_field, "") or "")
        name = str(getattr(user, self.name_field, "") or "")
        phone = str(getattr(user, self.phone_field, "") or "")
        url_token = URLToken(
            user, self.token_type, email=email, name=name, phone=phone, channel=channel
        )

        if not self._validate_preconditions(url_token, fail_silently):
            return url_token

        uidb64 = encode(getattr(user, self.encoding_field))
        token, ts = self._token_generator.make_token(user)
        link = f"{protocol}://{domain}:{port}/{path}?uid={uidb64}&key={token}"
        hash = hashlib.sha256(force_bytes(uidb64 + token)).hexdigest()
        expires_at = timezone.make_aware(ts) + timedelta(
            seconds=self._token_generator.timeout
        )

        url_token = url_token._(
            uidb64=uidb64, token=token, link=link, hash=hash, expires_at=expires_at
        )

        if self.send_enabled:
            url_token = self._send_link(
                url_token,
                template=template,
                email_subject=email_subject,
                fail_silently=fail_silently,
            )

        if self.logging_enabled:
            url_token._log()

        if url_token.exception and not fail_silently:
            raise url_token.exception

        return url_token

    def bulk_generate_tokenized_link(
        self,
        users: Iterable[object],
        path: str | Callable[[object], str] | None = None,
        domain: str | None = None,
        protocol: str | None = None,
        port: str | None = None,
        channel: Channel | None = None,
        template: Template | Callable[[URLToken], Template] | None = None,
        email_subject: str | None = None,
        fail_silently: bool | None = None,
    ) -> list[URLToken]:
        url_tokens, threads = [], []

        if users is None:
            return url_tokens

        # Define a helper function to execute generate_tokenized_link for each user
        def generate_link(user):
            url_token = self.generate_tokenized_link(
                user,
                path=path,
                domain=domain,
                protocol=protocol,
                port=port,
                channel=channel,
                template=template,
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
            fail_silently = self.fail_silently_on_check

        # decode uidb64
        try:
            decoded_attr = decode(uidb64)
        except DjangoUnicodeDecodeError:
            return None, None

        # user lookup
        user = self.user_model.objects.filter(
            **{self.encoding_field: decoded_attr}
        ).first()
        if user is None:
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
            fail_silently = self.fail_silently_on_callbacks

        callbacks_returns = self._token_generator.run_callbacks(
            user, callback_kwargs=callback_kwargs, fail_silently=fail_silently
        )

        return callbacks_returns


default_tokenizer = URLTokenizer()
