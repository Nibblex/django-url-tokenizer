from typing import Any

from django.conf import settings
from django.utils.module_loading import import_string

SETTINGS = getattr(settings, "URL_TOKENIZER_SETTINGS", {})


def str_import(functions: list) -> list:
    return [import_string(f) if isinstance(f, str) else f for f in functions]


def from_config(config: dict, key: str, default: Any) -> Any:
    return config.get(key, SETTINGS.get(key.upper(), default))
