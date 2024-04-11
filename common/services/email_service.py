import os
import boto3
from botocore.exceptions import ClientError


# Replace these with your AWS access key ID and secret access key
# Create an SES client
class EmailHandler:
    """
    A class for handling email-related functionality using Amazon SES.

    Attributes:
        aws_access_key_id (str): AWS Access Key ID for SES.
        aws_secret_access_key (str): AWS Secret Access Key for SES.
        aws_region (str): AWS Region for SES.

    Methods:
        read_html_template(template_file_path: str) -> str:
            Reads and returns the content of an HTML template file.

        send_otp_email(email: str, otp: str) -> None:
            Sends an email containing a one-time password (OTP) for password reset.

        send_mfa_otp_email(email: str, otp: str) -> None:
            Sends an email containing a one-time password (OTP) for multi-factor authentication (MFA).

        send_email_validation(email: str, token: str) -> None:
            Sends an email to validate the user's email address.

    Example:
        email_handler = EmailHandler()
        email_handler.send_otp_email('user@example.com', '123456')

    """
    def __init__(self):
        self.aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        self.aws_region = os.getenv("AWS_REGION")

    def read_html_template(self, template_file_path):
        """
        Reads and returns the content of an HTML template file.

        Args:
            template_file_path (str): The path to the HTML template file.

        Returns:
            str: The content of the HTML template.
        """
        with open(template_file_path, 'r') as file:
            return file.read()

    def send_otp_email(self,email,top):
        """
        Sends an email containing a one-time password (OTP) for password reset.

        Args:
            email (str): The recipient's email address.
            otp (str): The one-time password (OTP) is to be included in the email.

        Returns:
            None
        """
        ses_client = boto3.client('ses', aws_access_key_id=self.aws_access_key_id, aws_secret_access_key=self.aws_secret_access_key, region_name=self.aws_region)

        # Specify the sender's email address and recipient's email address
        sender_email = 'admin@truenil.io'
        recipient_email = email

        # Specify the email subject and body
        subject = 'OTP for reset password'
        # Read the HTML template from the file
        path_components = ['common', 'services', 'reset-otp.html']

        # Use os.path.join to create the full file path
        file_path = os.path.join(*path_components)
        body_html = self.read_html_template(file_path)

        # Replace placeholder with the OTP value
        body_html = body_html.replace('{{OTP}}', otp)
        # Create the email message
        message = {
            'Subject': {
                'Data': subject,
            },
            'Body': {
                'Html': {
                    'Data': body_html,
                },
            },
        }

        # Try to send the email
        try:
            response = ses_client.send_email(
                Source=sender_email,
                Destination={
                    'ToAddresses': [recipient_email],
                },
                Message=message,
            )
            print(f"Email sent! Message ID: {response['MessageId']}")

        except ClientError as e:
            print(f"Error sending email: {e.response['Error']['Message']}")
    def send_mfa_otp_email(self,email,top):
        """
        Sends an email containing a one-time password (OTP) for multi-factor authentication (MFA).

        Args:
            email (str): The recipient's email address.
            otp (str): The one-time password (OTP) is to be included in the email.

        Returns:
            None
        """
        ses_client = boto3.client('ses', aws_access_key_id=self.aws_access_key_id, aws_secret_access_key=self.aws_secret_access_key, region_name=self.aws_region)

        # Specify the sender's email address and recipient's email address
        sender_email = 'keshav@truenil.io'
        recipient_email = email

        # Specify the email subject and body
        subject = 'OTP for login'
        # Read the HTML template from the file
        path_components = ['common', 'services', 'mfa-otp.html']

        # Use os.path.join to create the full file path
        file_path = os.path.join(*path_components)
        body_html = self.read_html_template(file_path)

        # Replace placeholder with the OTP value
        body_html = body_html.replace('{{OTP}}', otp)
        # Create the email message
        message = {
            'Subject': {
                'Data': subject,
            },
            'Body': {
                'Html': {
                    'Data': body_html,
                },
            },
        }

        # Try to send the email
        try:
            response = ses_client.send_email(
                Source=sender_email,
                Destination={
                    'ToAddresses': [recipient_email],
                },
                Message=message,
            )
            print(f"Email sent! Message ID: {response['MessageId']}")

        except ClientError as e:
            print(f"Error sending email: {e.response['Error']['Message']}")

    def send_email_validation(self,email,token):
        """
        Sends an email to validate the user's email address.

        Args:
            email (str): The recipient's email address.
            token (str): The validation token to be included in the email.

        Returns:
            None
        """
        ses_client = boto3.client('ses', aws_access_key_id=self.aws_access_key_id, aws_secret_access_key=self.aws_secret_access_key, region_name=self.aws_region)

        # Specify the sender's email address and recipient's email address
        sender_email = 'keshav@truenil.io'
        recipient_email = email

        # Specify the email subject and body
        subject = 'Truenil Email Validation'
        # Read the HTML template from the file
        path_components = ['common', 'services', 'verify-user.html']

        # Use os.path.join to create the full file path
        file_path = os.path.join(*path_components)
        body_html = self.read_html_template(file_path)

        # Replace placeholder with the OTP value
        body_html = body_html.replace('{token}', token)
        # Create the email message
        message = {
            'Subject': {
                'Data': subject,
            },
            'Body': {
                'Html': {
                    'Data': body_html,
                },
            },
        }

        # Try to send the email
        try:
            response = ses_client.send_email(
                Source=sender_email,
                Destination={
                    'ToAddresses': [recipient_email],
                },
                Message=message,
            )
            print(f"Email sent! Message ID: {response['MessageId']}")

        except ClientError as e:
            print(f"Error sending email: {e.response['Error']['Message']}")
