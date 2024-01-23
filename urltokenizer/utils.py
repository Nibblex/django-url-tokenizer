from typing import Callable
from django.utils.module_loading import import_string


def str_import(functions: list[str | Callable]) -> list[Callable]:
    return [import_string(f) if isinstance(f, str) else f for f in functions]
