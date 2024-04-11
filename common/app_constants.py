class AppConstants:
    """
    A class containing constants for HTTP status codes and other application-related constants.

    Attributes:
        CODE_OK (int): HTTP status code for OK (200).
        CODE_INVALID_REQUEST (int): HTTP status code for Invalid Request (400).
        CODE_UNAUTHORIZED (int): HTTP status code for Unauthorized (401).
        CODE_FORBIDDEN (int): HTTP status code for Forbidden (403).
        CODE_INTERNAL_SERVER_ERROR (int): HTTP status code for Internal Server Error (500).
        CODE_NOT_IMPLEMENTED (int): HTTP status code for Not Implemented (501).
        CODE_BAD_GATEWAY (int): HTTP status code for Bad Gateway (502).
        CODE_SERVICE_UNAVAILABLE (int): HTTP status code for Service Unavailable (503).
        CODE_GATEWAY_TIMEOUT (int): HTTP status code for Gateway Timeout (504).
        SUCCESSFUL_STATUS_CODE (str): String representation of the successful status code ("200").
        UNSUCCESSFUL_STATUS_CODE (str): String representation of the unsuccessful status code ("500").

    Example:
        response_code = AppConstants.CODE_OK
        if response_code == AppConstants.CODE_OK:
            print("Request was successful.")
        elif response_code == AppConstants.CODE_INVALID_REQUEST:
            print("Invalid request.")
        # Other condition checks for different status codes.
    """
    CODE_OK = 200
    CODE_INVALID_REQUEST = 400
    CODE_UNAUTHORISED = 401
    CODE_FORBIDDEN = 403
    CODE_INTERNAL_SERVER_ERROR = 500
    CODE_NOT_IMPLEMENTED = 501
    CODE_BAD_GATEWAY = 502
    CODE_SERVICE_UNAVAILABLE = 503
    CODE_GATEWAY_TIMEOUT = 504
    SUCCESSFULL_STATUS_CODE = "200"
    UNSUCCESSFULL_STATUS_CODE = "500"
