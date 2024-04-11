import os

import jwt

def validate(headers):
    """
    Validates an access token extracted from the request headers.

    Args:
        headers (dict): A dictionary containing the request headers.

    Returns:
        tuple: A tuple containing:
            - email (str): The email address extracted from the access token.
            - organization (str): The organization information extracted from the access token.

    Note:
        This function expects the access token to be provided in the "Authorization" header
        with the format "Bearer <access_token>". It decodes the token using the provided secret key,
        checks for expiration and retrieves the email and organization claims.

    Example:
        headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
        email, organization = validate(headers)
        if email and organization:
            print(f"Token validated successfully. Email: {email}, Organization: {organization}")
        else:
            print("Token validation failed.")
    """
    try:
        token = headers["Authorization"]
        email = None
        organization = None
        data = token.split()
        if "Bearer" in data:
            access_token = data[1]
            secret_key = os.getenv("SECRET_KEY")
            decoded_payload = jwt.decode(access_token, secret_key, algorithms=['HS256'])
            # If the token is valid and not expired, you can access its claims
            email = decoded_payload['email']
            organization = decoded_payload['organization']
    except jwt.ExpiredSignatureError:
        # Handle token expiration
        print("Token has expired. Please generate a new one.")
    except jwt.InvalidTokenError:
        # Handle invalid token
        print("Invalid token. Authentication failed.")
    finally:
        return email,organization