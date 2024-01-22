from enum import Enum, unique


@unique
class ErrorCodes(Enum):
    invalid_token_type = "invalid_token_type"
    invalid_method = "invalid_method"
    send_precondition_execution_error = "send_precondition_execution_error"
    check_precondition_execution_error = "check_precondition_execution_error"
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


class SendPreconditionExecutionError(Exception):
    def __init__(self, message):
        self.message = message
        self.code = ErrorCodes.send_precondition_execution_error.value
        super().__init__(message)


class CheckPreconditionExecutionError(Exception):
    def __init__(self, message):
        self.message = message
        self.code = ErrorCodes.check_precondition_execution_error.value
        super().__init__(message)


class CallbackExecutionError(Exception):
    def __init__(self, message):
        self.message = message
        self.code = ErrorCodes.callback_execution_error.value
        super().__init__(message)
