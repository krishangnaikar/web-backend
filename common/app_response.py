from common.app_constants import AppConstants
from common.string_table import AppMessages


class AppResponse(dict):
    """
    A class representing a standardized response format for the application.

    Attributes:
        code (str): The HTTP status code indicating the result of the operation.
        data (dict): The data associated with the response.
        message (str): A descriptive message explaining the result of the operation.
        status (str): The status of the operation, typically indicating success or failure.

    Methods:
        __init__(self, code_param=AppConstants.UNSUCCESSFUL_STATUS_CODE, data_param={},
                 message_param=AppMessages.FAILED, status_param=AppMessages.FALSE):
            Initializes the AppResponse object with default or provided values.

        set_response(self, code_param, data_param, message_param, status_param):
            Sets the values for the response attributes.

    Example:
        response = AppResponse()
        response.set_response(AppConstants.CODE_OK, {'key': 'value'}, 'Operation successful', AppMessages.TRUE)
        print(response)
        {'code': 200, 'data': {'key': 'value'}, 'message': 'Operation successful', 'status': 'True'}
    """
    def __init__(self, code_param=AppConstants.UNSUCCESSFULL_STATUS_CODE, data_param={},
                 message_param=AppMessages.FAILED, status_param=AppMessages.FALSE):
        """
        Initializes the AppResponse object with default or provided values.

        Args:
            code_param (str): The HTTP status code. Defaults to "500".
            data_param (dict): The data associated with the response. Defaults to an empty dictionary.
            message_param (str): A descriptive message. Defaults to "FAILED".
            status_param (str): The status of the operation. Defaults to "FALSE".

        Args:
            code_param:
            data_param:
            message_param:
            status_param:
        """
        dict.__init__(self, code=code_param, data=data_param, message=message_param, status=status_param)

    def set_response(self, code_param, data_param, message_param, status_param):
        """
        Sets the values for the response attributes.

        Args:
            code_param (str): The HTTP status code.
            data_param (dict): The data associated with the response.
            message_param (str): A descriptive message.
            status_param (str): The status of the operation.
        """
        self['code'] = code_param
        self['data'] = data_param
        self['message'] = message_param
        self['status'] = status_param
