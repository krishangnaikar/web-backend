class AppMessages:
    """
    A class containing constant messages is used throughout the application.

    Constants:
        FAILED (str): A general message indicating failure.
        FALSE (bool): Boolean value representing false.
        OPERATION_SUCCESS (str): A message indicating the successful completion of an operation.
        OPERATION_FAILED (str): A message indicating failure in the operation.
        INTERNAL_ERROR (str): A message indicating an internal server error.

    Example:
        print(AppMessages.OPERATION_SUCCESS)
        'Operation Successfully Completed'
        print(AppMessages.FAILED)
        'failed'
        print(AppMessages.FALSE)
        False
    """
    FAILED = "failed"
    FALSE = False
    OPERATION_SUCCESS = "Operation Successfully Completed"
    OPERATION_FAILED = "Operation Failed"
    INTERNAL_ERROR = "Internal Server Error Occurred"
