from enum import Enum, unique

from django.utils.translation import gettext_lazy as _


@unique
class ErrorCodes(Enum):
    invalid_token_type = _("There is no token type with name '{token_type}'")
    invalid_method = _("User model has no method '{method_name}'")
    send_precondition_execution_error = _(
        "Error during send precondition '{pred}' execution"
    )
    check_precondition_execution_error = _(
        "Error during check precondition '{pred}' execution"
    )
    callback_execution_error = _("Error during callback '{callback}' execution")


class URLTokenizerError(Exception):
    def __init__(self, message, code, context=None, *args, **kwargs):
        self.message = message.format(*args, **kwargs)
        self.code = code
        self.context = context or {}

        super().__init__(self.message, code)
