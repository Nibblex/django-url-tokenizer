from typing import Any

from django.utils.module_loading import import_string

from .utils import SETTINGS


def serialize_user(
    user: object,
    *,
    related_serializers: dict[str, str] | None = None,
    **kwargs,
) -> dict[str, Any] | None:
    """
    Built-in callback that serializes the user using the configured USER_SERIALIZER.

    - USER_SERIALIZER must be a string path to a DRF serializer class.
    - related_serializers is an optional dict where:
        key   -> field_name on user
        value -> string path to DRF serializer class
    """

    user_serializer = SETTINGS.get("USER_SERIALIZER")
    if user_serializer is None:
        return None

    serializer_class = import_string(user_serializer)
    data = serializer_class(user).data

    if not related_serializers:
        return data

    for field_name, serializer_path in related_serializers.items():
        # Skip if user doesn't have the attribute
        if not hasattr(user, field_name):
            continue

        related_instance = getattr(user, field_name, None)
        if related_instance is None:
            continue

        serializer_cls = import_string(serializer_path)

        serialized_related = serializer_cls(related_instance).data

        data[field_name] = serialized_related

    return data


def patch_user(
    user: object, *, data: dict[str, Any] = None, **kwargs
) -> dict[str, Any] | None:
    """
    Built-in callback that updates the user using the configured USER_SERIALIZER.

        The USER_SERIALIZER setting should be a string path to a DRF serializer class that
        takes the user as input and updates it with the provided data. The updated user
        data is returned as a dictionary to be used in the callback.
    """

    user_serializer = SETTINGS.get("USER_SERIALIZER")
    if user_serializer is None or data is None:
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
