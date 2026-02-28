from django.utils.module_loading import import_string

from ..exceptions import ErrorCode, URLTokenizerError
from ..utils import SETTINGS


def serialize_user(user, user_serializer=None):
    """
    Built-in callback that serializes the user using the configured USER_SERIALIZER.

    The serializer class is resolved from the ``user_serializer`` argument first,
    then falls back to the ``USER_SERIALIZER`` key in ``URL_TOKENIZER_SETTINGS``.
    Returns ``None`` when no serializer class is configured.
    """
    serializer_class = user_serializer or SETTINGS.get("USER_SERIALIZER")
    if not serializer_class:
        return None

    if isinstance(serializer_class, str):
        serializer_class = import_string(serializer_class)

    try:
        return serializer_class(user).data
    except Exception as e:
        raise URLTokenizerError(
            ErrorCode.builtin_callback_serializer_error,
            context={"exception": e},
            serializer=getattr(serializer_class, "__name__", str(serializer_class)),
        ) from e
