import os
import boto3
from botocore.exceptions import ClientError


# Replace these with your AWS access key ID and secret access key
# Create an SES client
class EmailHandler:

    def __init__(self):
        self.aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        self.aws_region = os.getenv("AWS_REGION")

    def read_html_template(self, template_file_path):
        with open(template_file_path, 'r') as file:
            return file.read()

    def send_otp_email(self,email,otp):

        ses_client = boto3.client('ses', aws_access_key_id=self.aws_access_key_id, aws_secret_access_key=self.aws_secret_access_key, region_name=self.aws_region)

        # Specify the sender's email address and recipient's email address
        sender_email = 'keshav@truenil.io'
        recipient_email = email

        # Specify the email subject and body
        subject = 'OTP for reset password'
        # Read the HTML template from the file
        path_components = ['common', 'services', 'otp.html']

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
