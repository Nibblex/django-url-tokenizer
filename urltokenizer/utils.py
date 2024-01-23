from django.utils.module_loading import import_string


def str_import(functions: list) -> list:
    return [import_string(f) if isinstance(f, str) else f for f in functions]
