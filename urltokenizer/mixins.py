from enum import Enum

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _

from .tokenizer import Tokenizer


class URLTokenizerMixin:
    def __init__(self, *args, **kwargs):
        # Check if the model is the auth user model
        if self.__class__ != get_user_model():
            raise ImproperlyConfigured(
                _("URLTokenizerMixin must be used with the auth user model")
            )

    def generate_tokenized_link(
        self,
        token_type: str | Enum,
        domain: str = None,
        protocol: str = None,
        port: str = None,
        send_email: bool = False,
    ) -> tuple[str, str, str, bool]:
        tokenizer = Tokenizer(token_type)
        return tokenizer.generate_tokenized_link(
            self, domain=domain, protocol=protocol, port=port, send_email=send_email
        )

    def check_token(self, token_type: str | Enum, token: str, **kwargs) -> bool:
        tokenizer = Tokenizer(token_type)
        uidb64 = tokenizer.encode(getattr(self, tokenizer.encoding_field))
        return tokenizer.check_token(uidb64, token, **kwargs) is not None
