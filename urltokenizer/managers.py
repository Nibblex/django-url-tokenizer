from enum import Enum

from django.db import models

from .tokenizer import URLTokenizer


class URLTokenizerQueryset(models.QuerySet):
    def bulk_generate_tokenized_link(
        self,
        token_type: str | Enum | None = None,
        path: str | None = None,
        domain: str | None = None,
        protocol: str | None = None,
        port: str | None = None,
        email_subject: str | None = None,
        send_email: bool = False,
    ):
        tokenizer = URLTokenizer(token_type)
        return tokenizer.bulk_generate_tokenized_link(
            self,
            path=path,
            domain=domain,
            protocol=protocol,
            port=port,
            email_subject=email_subject,
            send_email=send_email,
        )


URLTokenizerManager = models.Manager.from_queryset(URLTokenizerQueryset)
