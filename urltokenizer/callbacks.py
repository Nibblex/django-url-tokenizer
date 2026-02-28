from django.utils.module_loading import import_string


def serialize_user(user, user_serializer=None):
    """
    Built-in callback that serializes the user using the configured user serializer.
    Returns the serialized user data, or None if no serializer is configured.
    """
    if user_serializer is None:
        return None
    if isinstance(user_serializer, str):
        user_serializer = import_string(user_serializer)
    return user_serializer(user).data


BUILTIN_CALLBACKS = {
    "serialize_user": serialize_user,
}
