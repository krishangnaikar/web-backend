class Messages:
    """
    A class containing constant messages is used throughout the application.

    Constants:
        FAILED (str): A general message indicating failure.
        FALSE (bool): Boolean value representing false.
        SUCCESS (str): A general message indicating success.
        TRUE (bool): Boolean value representing true.
        HEADER_CONTAINS (str): Message indicating the expected headers in a request.
        TOKEN_EXPIRED (str): Message indicating an expired authorization token.
        TOKEN_INVALID (str): Message indicating an invalid authorization token.
        USER_NOT (str): Message indicating that a user was not found.
        FRESHWORK_FAILED (str): Message indicating a failure in Freshwork user registration.
        FETCH_DATA_FAIL (str): Message indicating a failure in fetching card summary data.
        UNAUTHORIZED (str): Message indicating an unauthorized request.
        AUTHORIZATION_FAILED (str): Message indicating failed authorization due to an invalid token.
        AUTHORIZATION_MISSING (str): Message indicating missing authorization token in headers.
        EXCEPTION_JWT (str): Message indicating an exception during JWT token validation.
        USER_NOT_MOB_EMAIL (str): Message indicating mismatch in user mobile number or email ID.
        REPLACE_SUCCESS (str): Message indicating successful initiation of a new card issuance process.
        REPLACE_FAIL (str): Message indicating failure in the process to issue a new card.
        UPDATE_FW_CONTACT_SUCCESS (str): Message indicating successful update of Freshwork contact.
        UPDATE_FW_CONTACT_FAIL (str): Message indicating failure in updating Freshwork contact.
        USER_INFO (str): Message indicating mismatch in user information.
        CARD_BLOCKED (str): Message indicating a blocked card and instructions for replacement.
        CARD_BLOCKED_FAILED (str): Message indicating issues in blocking a card.
        NOT_MATCH (str): Message indicating that user information does not match.
        FETCH_MINI_STATEMENT_FAIL (str): Message indicating failure in fetching the mini statement.
        FETCH_MINI_STATEMENT_SUCCESS (str): Message indicating successful fetch of the mini statement.
        SOMETHING_WENT_WRONG (str): Message indicating a general failure with a request.
        CREDIT_DETAILS_NOT (str): Message indicating that user credit card details are not available.
        FETCH_CARD_SUMMARY (str): Message indicating successful fetch of card summary.
        USER_INFO_FAILED (str): Message indicating failure in finding a user with provided profile details.
        CARD_BLOCKED_SECOND (str): Second part of the message for blocked cards and replacement instructions.
        CARD_BLOCKED_FIRST (str): First part of the message for blocked cards.
        FRESH_WORK_ADD_FAILED (str): Message indicating failure in adding user information to Freshwork.
        USER_NOT_FOUND (str): Message indicating invalid customer ID or UUID.
        CARD_REPLACE_SECOND (str): Second part of the message for replaced cards and activation instructions.
        INVALID_FORMAT (str): Message indicating invalid format.
        TOKEN_URL (str): URL for Google OAuth2 token.
        PEOPLE_API_URL (str): URL for Google People API.
        SCOPE (str): OAuth2 scope for Google authentication.
        AUTHORIZATION_URL (str): URL for Google OAuth2 authorization.
    """
    FAILED = "failed"
    FALSE = False
    SUCCESS = "Success"
    TRUE = True
    HEADER_CONTAINS = "Header should contains deviceType, appVersion, ContentType, deviceId, device, " \
                      "Authorization those fields"
    TOKEN_EXPIRED = "Authorization token is Expired"
    TOKEN_INVALID = "Authorization token is Invalid"
    USER_NOT = "User not found"
    FRESHWORK_FAILED = "Fresh work user registration failed"
    FETCH_DATA_FAIL = 'Fetching card summary is failed'
    UNAUTHORIZED = 'Unauthorized request'
    AUTHORIZATION_FAILED = 'Invalid Authorization token'
    AUTHORIZATION_MISSING = 'Header should contain authorization token'
    EXCEPTION_JWT = "Exception occurred during validating the jwt token"
    USER_NOT_MOB_EMAIL = "User mobile number/email id not matching. Please provide the correct mobile number/email id"
    REPLACE_SUCCESS = "Process to issue a new card is initiated"
    REPLACE_FAIL = "Process to issue a new card failed"
    UPDATE_FW_CONTACT_SUCCESS = "OK"
    UPDATE_FW_CONTACT_FAIL = "Updating fw contact failed"
    USER_INFO = "user information not matched"
    CARD_BLOCKED = "Your card ending in %s has been reported as damaged and a new one has been sent to the residential address we have on file for you. When you receive your replacement card, please activate it by logging in to the Neu app."
    CARD_BLOCKED_FAILED = "Facing issues for blocking card"
    NOT_MATCH = "User information not matched. Please check your email/mobile number"
    FETCH_MINI_STATEMENT_FAIL = "Fetching the mini statement failed"
    FETCH_MINI_STATEMENT_SUCCESS = "Successfully fetched the mini statement"
    SOMETHING_WENT_WRONG = "something went wrong please try again"
    CREDIT_DETAILS_NOT = "User credit card details not available"
    FETCH_CARD_SUMMARY = "Successfully fetched card summary"
    USER_INFO_FAILED = "No user found with the given profile details"
    CARD_BLOCKED_SECOND = " has been reported as damaged and a new one has been sent to the residential address we have on file for you. When you receive your replacement card, please activate it by logging in to the Neu app."
    CARD_BLOCKED_FIRST = "Your card ending in "
    FRESH_WORK_ADD_FAILED = "Adding user information to fresh work failed"
    USER_NOT_FOUND = "Invalid customerid/uuid"
    CARD_REPLACE_SECOND = " has been terminated and a new one has been sent to the residential address we have on file for you. When you receive your new card, please activate it and update your card number with any retailers that used your previous card number for recurring payments."
    INVALID_FORMAT = "Invalid format"
    TOKEN_URL = 'https://oauth2.googleapis.com/token'
    PEOPLE_API_URL = 'https://people.googleapis.com/v1/people/me'
    SCOPE = 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/user.organization.read https://www.googleapis.com/auth/contacts.readonly'
    AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/auth'