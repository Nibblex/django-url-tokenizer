from typing import Any

from django.utils.module_loading import import_string

from .utils import SETTINGS


def serialize_user(user: object, **kwargs) -> dict[str, Any] | None:
    """
    Built-in callback that serializes the user using the configured USER_SERIALIZER.

    The serializer class is resolved from the ``user_serializer`` argument first,
    then falls back to the ``USER_SERIALIZER`` key in ``URL_TOKENIZER_SETTINGS``.
    Returns ``None`` when no serializer class is configured.
    """

    user_serializer = SETTINGS.get("USER_SERIALIZER")
    if user_serializer is None:
        return None

    serializer_class = import_string(user_serializer)

    return serializer_class(user).data


def patch_user(user: object, data: dict[str, Any], **kwargs) -> dict[str, Any] | None:
    """
    Built-in callback that updates the user using the configured USER_SERIALIZER.

    The serializer class is resolved from the ``user_serializer`` argument first,
    then falls back to the ``USER_SERIALIZER`` key in ``URL_TOKENIZER_SETTINGS``.
    Returns ``None`` when no serializer class is configured.
    """

    user_serializer = SETTINGS.get("USER_SERIALIZER")
    if user_serializer is None:
        return None

    serializer_class = import_string(user_serializer)

    serializer = serializer_class(user, data=data, partial=True)
    serializer.is_valid(raise_exception=True)
    serializer.save()

    return serializer.data


# Registry mapping built-in callback names to their implementations.
# Add new built-in callbacks here to make them available via the
# ``builtin`` key in the callback configuration.
BUILTIN_CALLBACKS = {
    "serialize_user": serialize_user,
    "patch_user": patch_user,
}
