import hashlib
import inspect
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from functools import partial
from typing import Any

from django.conf import settings
from django.db.utils import ProgrammingError
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.encoding import force_bytes
from django.utils.http import base36_to_int, int_to_base36
from django.utils.module_loading import import_string

from .exceptions import ErrorCode, URLTokenizerError
from .models import Log
from .utils import _from_config, _parse_preconditions, encode


class TokenGenerator:
    """
    Strategy object used to generate and check tokens.
    """

    key_salt = "django.contrib.auth.tokens.PasswordResetTokenGenerator"
    algorithm = None
    _secret = None

    @property
    def _now(self) -> datetime:
        return datetime.now()

    @property
    def secret(self) -> str:
        return self._secret or settings.SECRET_KEY

    @secret.setter
    def secret(self, value: str):
        self._secret = value

    def __init__(self, token_config: dict[str, Any] | None = None):
        token_config = token_config or {}

        # token
        self.algorithm = self.algorithm or "sha256"
        self.encoding_field = _from_config(token_config, "encoding_field", "pk")
        self.attributes = _from_config(token_config, "attributes", [])
        self.timeout = _from_config(token_config, "timeout", 60)

        # check
        self.check_preconditions = _parse_preconditions(
            token_config, "check_preconditions"
        )
        self.check_logs = _from_config(token_config, "check_logs", False)
        self.user_serializer = _from_config(token_config, "user_serializer", None)
        self.callbacks = _from_config(token_config, "callbacks", [])

    @staticmethod
    def __num_ms(dt) -> int:
        return int((dt - datetime(2001, 1, 1)).total_seconds() * 1000)

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

    def _get_log(self, user: object, token: str) -> Log | None:
        uidb64 = encode(getattr(user, self.encoding_field))
        token_hash = hashlib.sha256(force_bytes(uidb64 + token)).hexdigest()

        try:
            log = Log.objects.filter(hash=token_hash).last()
        except ProgrammingError:
            return None

        return log

    def _validate_preconditions(
        self, user: object, token: str, fail_silently: bool = False
    ) -> bool:
        for k, pred in self.check_preconditions.items():
            try:
                if not pred(user):
                    log = self._get_log(user, token)
                    if log is not None:
                        log.check_precondition_failed = k
                        log.save(update_fields=["check_precondition_failed"])
                    return False
            except Exception as e:
                if fail_silently:
                    return False

                raise URLTokenizerError(
                    ErrorCode.check_precondition_execution_error,
                    context={"exception": e},
                    pred=pred,
                ) from e

        return True

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

    def make_token(self, user: object) -> tuple[str, datetime]:
        """
        Return a token that can be used once for the given user.
        """
        now = self._now
        return self._make_token_with_timestamp(user, self.__num_ms(now)), now

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
        if not user:
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
        if self.timeout and (self.__num_ms(self._now) - ts) / 1000 > self.timeout:
            return False, None

        # Check the preconditions
        if not self._validate_preconditions(user, token, fail_silently):
            return False, None

        # Check log
        log = None
        if self.check_logs:
            log = self._get_log(user, token)
            if log is None or log.checked:
                return False, None

            log._check()

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
        Run the configured callbacks for the given user. Callbacks can be
        configured to receive kwargs, and to return values that will be collected
        and returned by this method.
        """

        def resolve_callback(callback: dict[str, Any]):
            if callback.get("method"):
                return getattr(user, callback["method"], None)

            if callback.get("path"):
                return import_string(callback["path"])

            if callback.get("lambda"):
                return partial(callback["lambda"], user)

            raise URLTokenizerError(ErrorCode.callback_configuration_error)

        def extract_kwargs(
            method, available_kwargs: list[dict[str, Any]], defaults: dict
        ):
            signature = inspect.signature(method)
            param_names = set(signature.parameters.keys())

            for i, kw in enumerate(available_kwargs):
                if set(kw.keys()).issubset(param_names):
                    selected = available_kwargs.pop(i)
                    break
            else:
                selected = {}

            final_kwargs = {**selected, **defaults}

            return final_kwargs

        available_kwargs = list(callback_kwargs or [])
        results = defaultdict(list)

        for callback in self.callbacks:
            try:
                method = resolve_callback(callback)

                if not callable(method):
                    raise URLTokenizerError(
                        ErrorCode.invalid_method,
                        method_name=method.__name__ if method else None,
                    )

                kwargs = extract_kwargs(
                    method,
                    available_kwargs,
                    callback.get("defaults", {}),
                )

                result = method(**kwargs)

                if callback.get("return_value"):
                    results[method.__name__].append(result)

            except Exception as e:
                if not fail_silently:
                    raise URLTokenizerError(
                        ErrorCode.callback_execution_error,
                        context={"exception": e},
                        callback=method.__name__ if method else None,
                    ) from e

        return results


# A singleton instance to use by default
# expiration time is 60 seconds by default
default_token_generator = TokenGenerator()
