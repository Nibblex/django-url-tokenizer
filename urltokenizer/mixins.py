from enum import Enum
from typing import Iterable, Tuple

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _

from .tokenizer import URLTokenizer


class URLTokenizerMixin:
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
        send_email: bool = False,
    ) -> Tuple[str, str, str, bool]:
        tokenizer = URLTokenizer(token_type)
        return tokenizer.generate_tokenized_link(
            self,
            path=path,
            domain=domain,
            protocol=protocol,
            port=port,
            send_email=send_email,
        )

    def check_token(
        self,
        token_type: str | Enum | None = None,
        token: str | None = None,
        callback_kwargs: Iterable[dict] = [],
        fail_silently: bool | None = None,
    ) -> bool:
        tokenizer = URLTokenizer(token_type)
        uidb64 = tokenizer.encode(getattr(self, tokenizer.encoding_field))

        if tokenizer.check_token(uidb64, token) is None:
            return False

        tokenizer.run_callbacks(
            self, callback_kwargs=callback_kwargs, fail_silently=fail_silently
        )

        return True
