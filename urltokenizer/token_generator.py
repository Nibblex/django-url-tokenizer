from datetime import datetime

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.http import base36_to_int, int_to_base36
from django.utils.translation import gettext_lazy as _


class TokenGenerator:
    """
    Strategy object used to generate and check tokens for the password
    reset mechanism.
    """

    key_salt = "django.contrib.auth.tokens.PasswordResetTokenGenerator"
    algorithm = None
    _secret = None

    def __init__(
        self,
        attributes: list = [],
        preconditions: list = {},
        callbacks: list = [],
        timeout: int = 60,
    ):
        self.algorithm = self.algorithm or "sha256"
        self.attributes = attributes
        self.preconditions = preconditions
        self.callbacks = callbacks
        self.timeout = timeout

    def _get_secret(self):
        return self._secret or settings.SECRET_KEY

    def _set_secret(self, secret):
        self._secret = secret

    secret = property(_get_secret, _set_secret)

    @property
    def __now(self):
        return datetime.now()

    @staticmethod
    def __num_seconds(dt):
        return int((dt - datetime(2001, 1, 1)).total_seconds())

    def make_token(self, user):
        """
        Return a token that can be used once to do a password reset
        for the given user.
        """
        return self._make_token_with_timestamp(user, self.__num_seconds(self.__now))

    def check_token(self, user, token):
        """
        Check that a password reset token is correct for a given user.
        """
        if not (user and token):
            return False
        # Parse the token
        try:
            ts_b36, _ = token.split("-")
        except ValueError:
            return False

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False

        # Check that the timestamp/uid has not been tampered with
        if not constant_time_compare(self._make_token_with_timestamp(user, ts), token):
            return False

        # Check the timestamp is within limit.
        if (self.__num_seconds(self.__now) - ts) > self.timeout:
            return False

        # Check that the user attribute values meet the preconditions
        preconditions = self.preconditions.items()
        if not all(
            getattr(user, attribute) == value for attribute, value in preconditions
        ):
            return False

        return True

    def run_callbacks(self, user, **kwargs):
        """
        Run callbacks for a given user.
        """
        for callback in self.callbacks:
            # Search for the callback method on the user model
            method = getattr(user, callback.get("method"), None)
            if method is None:
                continue

            # Filter the kwargs to only include the ones that the callback accepts
            kwargs = {
                key: value
                for key, value in kwargs.items()
                if key in callback.get("kwargs", [])
            }
            # Add the default kwargs
            kwargs.update(callback.get("defaults", {}))

            # Execute the callback
            try:
                method(**kwargs)
            except Exception as e:
                raise ValidationError(_("failed to execute callback")) from e

    def _make_token_with_timestamp(self, user, timestamp):
        # timestamp is number of seconds since 2001-1-1. Converted to base 36,
        # this gives us a 6 digit string until about 2069.
        ts_b36 = int_to_base36(timestamp)
        hash_string = salted_hmac(
            self.key_salt,
            self._make_hash_value(user, timestamp),
            secret=self.secret,
            algorithm=self.algorithm,
        ).hexdigest()[
            ::2
        ]  # Limit to shorten the URL.
        return f"{ts_b36}-{hash_string}"

    def _make_hash_value(self, user, timestamp):
        """
        Hash the user's primary key and some user attributes to make sure that
        the token is invalidated when the user changes these attributes.
        """
        attributes = [getattr(user, attribute) for attribute in self.attributes]
        return f"{user.pk}{timestamp}{attributes}"


# A singleton instance to use by default, it only espires with the timestamp (60 by default)
default_token_generator = TokenGenerator()
