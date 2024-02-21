import hashlib
import inspect
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from django.conf import settings
from django.db.utils import ProgrammingError
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.encoding import force_bytes
from django.utils.http import base36_to_int, int_to_base36
from django.utils.module_loading import import_string

from .exceptions import ErrorCode, URLTokenizerError
from .models import Log
from .utils import SETTINGS, encode, from_config, str_import


class TokenGenerator:
    """
    Strategy object used to generate and check tokens.
    """

    key_salt = "django.contrib.auth.tokens.PasswordResetTokenGenerator"
    algorithm = None
    _secret = None

    @property
    def __now(self) -> datetime:
        return datetime.now()

    @property
    def secret(self) -> str:
        return self._secret or settings.SECRET_KEY

    @secret.setter
    def secret(self, value: str):
        self._secret = value

    def __init__(self, token_config: dict[str, Any] | None = None):
        token_config = token_config or {}

        check_preconditions = str_import(
            SETTINGS.get("CHECK_PRECONDITIONS", [])
            + token_config.get("check_preconditions", [])
        )

        # token
        self.algorithm = self.algorithm or "sha256"
        self.encoding_field = from_config(token_config, "encoding_field", "pk")
        self.attributes = from_config(token_config, "attributes", [])
        self.timeout = from_config(token_config, "timeout", 60)

        # check
        self.check_preconditions = check_preconditions
        self.check_logs = from_config(token_config, "check_logs", False)
        self.user_serializer = from_config(token_config, "user_serializer", None)
        self.callbacks = from_config(token_config, "callbacks", [])

    @staticmethod
    def __num_seconds(dt) -> int:
        return int((dt - datetime(2001, 1, 1)).total_seconds())

    def _make_hash_value(self, user: object, timestamp: int) -> str:
        """
        Hash the user's primary key and some user attributes to make sure that
        the token is invalidated when the user changes these attributes.
        """
        attributes = [getattr(user, attribute) for attribute in self.attributes]
        return f"{user.pk}{timestamp}{attributes}"

    def _make_token_with_timestamp(self, user: object, timestamp: int) -> str:
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

    # helpers

    @staticmethod
    def _check_log(uidb64: str, token: str) -> Log | None:
        hash = hashlib.sha256(force_bytes(uidb64 + token)).hexdigest()
        try:
            log = Log.objects.filter(hash=hash).first()
        except ProgrammingError:
            return None

        if log is None or log.checked:
            return None

        log.checked_at = timezone.now()
        log.save(update_fields=["checked_at"])

        return log

    def _update_user_data(
        self, user: object, user_data: dict[str, Any], fail_silently: bool = False
    ):
        user_serializer = import_string(self.user_serializer)
        serializer = user_serializer(user, data=user_data, partial=True)

        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            if not fail_silently:
                raise URLTokenizerError(
                    ErrorCode.user_serializer_error,
                    serializer=self.user_serializer,
                    context={"exception": e},
                ) from e
        else:
            serializer.save()

    def make_token(self, user: object) -> str:
        """
        Return a token that can be used once for the given user.
        """
        return self._make_token_with_timestamp(user, self.__num_seconds(self.__now))

    def check_token(
        self,
        user: object,
        token: str,
        user_data: dict[str, Any] | None = None,
        fail_silently: bool = False,
    ) -> tuple[bool, Log | None]:
        """
        Check that a token is correct for a given user.
        """
        if not (user and token):
            return False, None

        # Parse the token
        try:
            ts_b36, _ = token.split("-")
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False, None

        # Check that the timestamp/uid has not been tampered with
        if not constant_time_compare(self._make_token_with_timestamp(user, ts), token):
            return False, None

        # Check the timestamp is within limit.
        if self.timeout and (self.__num_seconds(self.__now) - ts) > self.timeout:
            return False, None

        # Check the preconditions
        for pred in self.check_preconditions:
            try:
                if not pred(user):
                    return False, None
            except Exception as e:
                if fail_silently:
                    return False, None

                raise URLTokenizerError(
                    ErrorCode.check_precondition_execution_error,
                    context={"exception": e},
                    pred=pred,
                ) from e

        # Check log
        log = None
        if self.check_logs:
            log = self._check_log(encode(getattr(user, self.encoding_field)), token)
            if log is None:
                return False, None

        # update user data
        if user_data and self.user_serializer:
            self._update_user_data(user, user_data, fail_silently)

        return True, log

    def run_callbacks(
        self,
        user: object,
        callback_kwargs: Iterable[dict[str, Any]] | None = None,
        fail_silently: bool = False,
    ) -> dict[str, list[Any]]:
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

        callback_kwargs_copy = list(callback_kwargs or []).copy()

        callbacks_returns = defaultdict(list)
        for callback in self.callbacks:
            method_name = callback.get("method")
            method = getattr(user, method_name, None)

            if method is None:
                if fail_silently:
                    continue

                raise URLTokenizerError(ErrorCode.invalid_method, method_name=method_name)

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
                        ErrorCode.callback_execution_error,
                        context={"exception": e},
                        callback=method_name,
                    ) from e

                continue

            if callback.get("return_value", False):
                callbacks_returns[method_name].append(callback_return)

        return callbacks_returns


# A singleton instance to use by default
# expiration time is 60 seconds by default
default_token_generator = TokenGenerator()
