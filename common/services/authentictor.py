import secrets
import base64

import pyotp
# Generate a random secret key
def generate_mfa_uri(email):
    secret_key = base64.b32encode(secrets.token_bytes(20)).decode('utf-8')
    # Generate a QR code URL
    otp_url = pyotp.totp.TOTP(secret_key).provisioning_uri(email, issuer_name='Truenil')
    return secret_key,otp_url

def validate_otp(user_provided_code,secret_key):
    totp = pyotp.TOTP(secret_key)
    is_valid = totp.verify(user_provided_code)

    if is_valid:
        # Authentication successful
        print("Authentication successful")
        return user_provided_code
    else:
        # Authentication failed
        return ""