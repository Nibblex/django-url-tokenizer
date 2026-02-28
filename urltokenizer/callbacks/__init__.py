from .builtins import serialize_user

# Registry mapping built-in callback names to their implementations.
# Add new built-in callbacks here to make them available via the
# ``builtin`` key in the callback configuration.
BUILTIN_CALLBACKS = {
    "serialize_user": serialize_user,
}
