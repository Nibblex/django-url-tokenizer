from enum import Enum, unique


@unique
class ErrorCodes(Enum):
    invalid_token_type = "invalid_token_type"
    invalid_method = "invalid_method"
    callback_execution_error = "callback_execution_error"


class InvalidTokenTypeError(Exception):
    def __init__(self, message):
        self.message = message
        self.code = ErrorCodes.invalid_token_type.value
        super().__init__(message)


class InvalidMethodError(Exception):
    def __init__(self, message):
        self.message = message
        self.code = ErrorCodes.invalid_method.value
        super().__init__(message)


class CallbackExecutionError(Exception):
    def __init__(self, message):
        self.message = message
        self.code = ErrorCodes.callback_execution_error.value
        super().__init__(message)
