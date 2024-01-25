import inspect
from datetime import datetime

from django.conf import settings
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.http import base36_to_int, int_to_base36

from .exceptions import URLTokenizerError, ErrorCodes
from .utils import str_import


class TokenGenerator:
    """
    Strategy object used to generate and check tokens.
    """

    key_salt = "django.contrib.auth.tokens.PasswordResetTokenGenerator"
    algorithm = None
    _secret = None

    def __init__(
        self,
        attributes: list = [],
        check_preconditions: list = [],
        callbacks: list = [],
        timeout: int = 60,
    ):
        self.algorithm = self.algorithm or "sha256"
        self.attributes = attributes
        self.check_preconditions = str_import(check_preconditions)
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
        Return a token that can be used once for the given user.
        """
        return self._make_token_with_timestamp(user, self.__num_seconds(self.__now))

    def check_token(self, user, token, fail_silently=False):
        """
        Check that a token is correct for a given user.
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
        if self.timeout and (self.__num_seconds(self.__now) - ts) > self.timeout:
            return False

        # Check the preconditions
        for pred in self.check_preconditions:
            try:
                if not pred(user):
                    return False
            except Exception as e:
                if fail_silently:
                    return False

                raise URLTokenizerError(
                    ErrorCodes.check_precondition_execution_error.value,
                    ErrorCodes.check_precondition_execution_error.name,
                    context=dict(exception=e),
                    pred=pred,
                ) from e

        return True

    def run_callbacks(self, user, callback_kwargs=[], fail_silently=False):
        """
        Run callbacks for a given user.
        """

        def pop_next_matching_kwargs(kwargs, params):
            """
            Pop the next matching kwargs from the list of kwargs.
            """
            for i, kwarg in enumerate(kwargs):
                if set(kwarg.keys()).issubset(params):
                    return kwargs.pop(i)
            return {}

        callback_kwargs_copy = list(callback_kwargs).copy()

        callbacks_returns = {}
        for callback in self.callbacks:
            method_name = callback.get("method")
            # Search for the callback method on the user model
            method = getattr(user, method_name, None)
            if method is None:
                if fail_silently:
                    continue

                raise URLTokenizerError(
                    ErrorCodes.invalid_method.value,
                    ErrorCodes.invalid_method.name,
                    method_name=method_name,
                )

            # Get the kwargs for the callback method
            signature = inspect.signature(method)
            kwargs = pop_next_matching_kwargs(
                callback_kwargs_copy, signature.parameters.keys()
            )

            # Add the default kwargs
            kwargs.update(callback.get("defaults", {}))

            # Execute the callback
            try:
                callback_return = method(**kwargs)
            except Exception as e:
                if not fail_silently:
                    raise URLTokenizerError(
                        ErrorCodes.callback_execution_error.value,
                        ErrorCodes.callback_execution_error.name,
                        context=dict(exception=e),
                        callback=method_name,
                    ) from e

                continue

            # callbacks_returns is a dict of lists
            # each list contains the return values of the callback methods
            if callback.get("return_value", False):
                callbacks_returns.setdefault(method_name, []).append(callback_return)

        return callbacks_returns

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
