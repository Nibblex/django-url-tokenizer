from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from functools import reduce
from typing import Any

from jinja2 import Template as JinjaTemplate

from django.conf import settings
from django.db.utils import ProgrammingError
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.module_loading import import_string

from .enums import Channel
from .exceptions import URLTokenizerError
from .models import Log

SETTINGS = getattr(settings, "URL_TOKENIZER_SETTINGS", {})


def _from_config(config: dict[str, Any], key: str, default: Any) -> Any:
    return config.get(key, SETTINGS.get(key.upper(), default))


def _parse_preconditions(
    config: dict[str, Any], key: str
) -> dict[str, Callable[[object], bool]]:
    preconditions = SETTINGS.get(key.upper(), {})
    preconditions.update(SETTINGS.get("PRECONDITIONS", {}))
    preconditions.update(config.get(key, {}))
    preconditions.update(config.get("preconditions", {}))

    return {
        key: import_string(pred) if isinstance(pred, str) else pred
        for key, pred in preconditions.items()
    }


def parse_path(path: str | Callable[[object], str], user: object) -> str:
    if callable(path):
        path = path(user)

    return path.strip("/")


def rgetattr(obj, attr, *args):
    def f(obj, attr):
        return getattr(obj, attr, *args)

    return reduce(f, [obj] + attr.split("."))


def rhasattr(obj, attr):
    def f(obj, attr):
        return hasattr(obj, attr)

    return reduce(f, [obj] + attr.split("."))


def encode(s: Any) -> str:
    return urlsafe_base64_encode(force_bytes(s))


def decode(s: bytes | str) -> str:
    return force_str(urlsafe_base64_decode(s))


@dataclass
class URLToken:
    user: object
    type: str
    created_at: datetime = timezone.now()
    expires_at: datetime | None = None
    uidb64: str = ""
    token: str = ""
    link: str = ""
    hash: str | None = None
    email: str = ""
    name: str = ""
    phone: str = ""
    channel: Channel | None = None
    precondition_failed: str | None = None
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
                expires_at=self.expires_at,
                token_type=self.type,
                uidb64=self.uidb64,
                hash=self.hash,
                email=self.email,
                name=self.name,
                phone=self.phone,
                channel=self.channel,
                send_precondition_failed=self.precondition_failed,
                sent=self.sent,
                errors=self.exception.__repr__() if self.exception else None,
                user=self.user,
            )

            return self.log

        return None


class Template:
    def __init__(self, id: str, plain_content: str, context: dict[str, Any]):
        self.id = id
        self.plain_content = plain_content
        self.context = context
        self.params = self._params_from_plain_content

    @property
    def _params_from_plain_content(self) -> list[str]:
        def is_underscore(s: str) -> bool:
            import string

            return not s[0].isdigit() and all(
                c in string.ascii_lowercase + "_" + string.digits for c in s
            )

        params = set()
        for param in self.plain_content.split("{{")[1:]:
            param = param.split("}}")[0].replace(" ", "")
            if is_underscore(param) or param.strip().startswith("#each"):
                params.add(param.replace("#each", ""))

        return list(params)

    @staticmethod
    def _parse_context(
        url_token: URLToken,
        data: dict[str, Any] | Callable[[URLToken], dict[str, Any]] | None,
    ) -> dict[str, Any]:
        if data is None:
            return {}

        if callable(data):
            return data(url_token)

        return {
            key: value(url_token) if callable(value) else value
            for key, value in data.items()
        }

    def get_template_data(self, url_token: URLToken) -> dict[str, Any]:
        data = {
            k: rgetattr(url_token.user, k)
            for k in self.params
            if rhasattr(url_token.user, k)
        }
        data.update(self._parse_context(url_token, self.context))
        return data

    def render(self, url_token: URLToken) -> str:
        template = JinjaTemplate(
            self.plain_content.replace("{{{", "{{").replace("}}}", "}}")
        )
        return template.render(self.get_template_data(url_token))
