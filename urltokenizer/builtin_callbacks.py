from django.utils.module_loading import import_string

from .utils import SETTINGS


def serialize_user(user, user_serializer_path=None):
    """
    Built-in callback that serializes the user using the USER_SERIALIZER
    configured in URL_TOKENIZER_SETTINGS. Returns the serialized user data.
    """
    serializer_path = user_serializer_path or SETTINGS.get("USER_SERIALIZER")
    if not serializer_path:
        return None

    serializer_class = import_string(serializer_path)
    return serializer_class(user).data


BUILTIN_CALLBACKS = {
    "serialize_user": serialize_user,
}
