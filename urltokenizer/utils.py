from typing import Callable
from django.utils.module_loading import import_string


def map_functions(functions: list[str | Callable]) -> list[Callable]:
    return [import_string(f) if isinstance(f, str) else f for f in functions]
