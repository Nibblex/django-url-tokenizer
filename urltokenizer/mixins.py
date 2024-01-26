from enum import Enum
from typing import Iterable

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _

from .enums import Channel


class URLTokenizerMixin:
    @property
    def last_channel(self):
        log = self.log_set.last()
        return log.channel if log else None

    def __init__(self, *args, **kwargs):
        # Check if the model is the auth user model
        if self.__class__ != get_user_model():
            raise ImproperlyConfigured(
                _("URLTokenizerMixin must be used with the auth user model")
            )

    def generate_tokenized_link(
        self,
        token_type: str | Enum | None = None,
        path: str | None = None,
        domain: str | None = None,
        protocol: str | None = None,
        port: str | None = None,
        channel: Channel | None = None,
        email_subject: str | None = None,
        fail_silently: bool | None = None,
    ):
        from .tokenizer import URLTokenizer

        tokenizer = URLTokenizer(token_type)
        return tokenizer.generate_tokenized_link(
            self,
            path=path,
            domain=domain,
            protocol=protocol,
            port=port,
            channel=channel,
            email_subject=email_subject,
            fail_silently=fail_silently,
        )

    def check_token(
        self,
        token_type: str | Enum | None = None,
        token: str | None = None,
        callback_kwargs: Iterable = [],
        fail_silently: bool | None = None,
    ):
        from .tokenizer import URLTokenizer

        tokenizer = URLTokenizer(token_type)
        uidb64 = tokenizer.encode(getattr(self, tokenizer.encoding_field))

        user, log = tokenizer.check_token(uidb64, token)
        if not user:
            return False, log, {}

        callbacks_returns = tokenizer.run_callbacks(
            self, callback_kwargs=callback_kwargs, fail_silently=fail_silently
        )

        return True, log, callbacks_returns
