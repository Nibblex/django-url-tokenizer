from enum import Enum, unique


@unique
class Channel(Enum):
    """Enumeration of the different channels that can be used to send links."""

    EMAIL = "email"
    SMS = "sms"
