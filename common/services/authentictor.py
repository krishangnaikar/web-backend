import secrets
import base64

import pyotp
# Generate a random secret key
def generate_mfa_uri(email):
    """
    Generates a secret key and a provisioning URI for Multi-Factor Authentication (MFA).

    Args:
        email (str): The email address associated with the user for whom the MFA is generated.

    Returns:
        tuple: A tuple containing:
            - secret_key (str): The base32-encoded secret key used for generating one-time passwords.
            - otp_url (str): The provisioning URI for setting up MFA, suitable for QR code generation.

    Example:
        email = "user@example.com"
        secret_key, otp_url = generate_mfa_uri(email)
        print("Secret Key:", secret_key)
        print("Provisioning URI:", otp_url)

    """
    secret_key = base64.b32encode(secrets.token_bytes(20)).decode('utf-8')
    # Generate a QR code URL
    otp_url = pyotp.totp.TOTP(secret_key).provisioning_uri(email, issuer_name='Truenil')
    return secret_key,otp_url

def validate_otp(user_provided_code,secret_key):
    """
    Validates the user-provided one-time password (OTP) against a given secret key.

    Args:
        user_provided_code (str): The OTP entered by the user for validation.
        secret_key (str): The base32-encoded secret key associated with the user.

    Returns:
        str: If the OTP is valid, return the validated OTP. If invalid, returns an empty string.

    Example:
        user_code = "123456"  # Replace with the actual user-provided OTP
        secret_key = "JBSWY3DPEHPK3PXP"  # Replace with the actual secret key
        result = validate_otp(user_code, secret_key)
        if result:
            print(f"Authentication successful. Validated OTP: {result}")
        else:
            print("Authentication failed. Invalid OTP.")
    """
    totp = pyotp.TOTP(secret_key)
    is_valid = totp.verify(user_provided_code)

    if is_valid:
        # Authentication successful
        print("Authentication successful")
        return user_provided_code
    else:
        # Authentication failed
        return ""
