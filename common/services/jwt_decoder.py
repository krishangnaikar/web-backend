import os

import jwt

def validate(headers):
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