from enum import Enum
from typing import Callable

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils.translation import gettext_lazy as _

from .enums import Channel
from .tokenizer import URLToken
from .utils import Template


class URLTokenizerQueryset(models.QuerySet):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Check if the QuerySet's model is the auth user model
        if self.model and self.model != get_user_model():
            raise ImproperlyConfigured(
                _("URLTokenizerManager must be used with the auth user model")
            )

    def bulk_generate_tokenized_link(
        self,
        token_type: str | Enum | None = None,
        path: str | Callable[[object], str] | None = None,
        domain: str | None = None,
        protocol: str | None = None,
        port: str | None = None,
        channel: Channel | None = None,
        template: Template | Callable[[URLToken], Template] | None = None,
        email_subject: str | None = None,
        fail_silently: bool | None = None,
    ) -> list[URLToken]:
        from .tokenizer import URLTokenizer

        tokenizer = URLTokenizer(token_type)

        return tokenizer.bulk_generate_tokenized_link(
            self,
            path=path,
            domain=domain,
            protocol=protocol,
            port=port,
            channel=channel,
            template=template,
            email_subject=email_subject,
            fail_silently=fail_silently,
        )


URLTokenizerManager = models.Manager.from_queryset(URLTokenizerQueryset)
