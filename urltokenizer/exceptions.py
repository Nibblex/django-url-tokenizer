from enum import Enum, unique
from typing import Any

from django.utils.translation import gettext_lazy as _


@unique
class ErrorCode(Enum):
    invalid_token_type = _("There is no token type with name '{token_type}'")
    invalid_method = _("method '{method_name}' does not exist or is not callable")
    no_email = _("User does not have an email address associated with their account")
    no_phone = _("User does not have a phone number associated with their account")
    send_precondition_execution_error = _(
        "Error during send precondition '{pred}' execution"
    )
    check_precondition_execution_error = _(
        "Error during check precondition '{pred}' execution"
    )
    user_serializer_error = _("'is_valid' method from {serializer} returned False")
    callback_configuration_error = _(
        "Callback must include one of following keys: 'method', 'path' or 'lambda'"
    )
    callback_execution_error = _("Error during callback '{callback}' execution")


class URLTokenizerError(Exception):
    def __init__(
        self,
        error_code: ErrorCode,
        context: dict[str, Any] | None = None,
        *args,
        **kwargs,
    ):
        self.message = error_code.value.format(*args, **kwargs)
        self.code = error_code.name
        self.context = context or {}

    def __repr__(self) -> str:
        return "URLTokenizerError({}, code={}, context={})".format(
            self.message, self.code, self.context
        )

    def __str__(self) -> str:
        return f"{self.message} (code={self.code}, context={self.context})"
