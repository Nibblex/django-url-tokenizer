from collections.abc import Callable
from typing import Any

from django.conf import settings
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.module_loading import import_string

SETTINGS = getattr(settings, "URL_TOKENIZER_SETTINGS", {})


def _from_config(config: dict[str, Any], key: str, default: Any) -> Any:
    return config.get(key, SETTINGS.get(key.upper(), default))


def _str_import(
    functions: list[str | Callable[[object], bool]]
) -> list[Callable[[object], bool]]:
    return [import_string(f) if isinstance(f, str) else f for f in functions]


def encode(s: Any) -> str:
    return urlsafe_base64_encode(force_bytes(s))


def decode(s: bytes | str) -> str:
    return force_str(urlsafe_base64_decode(s))
