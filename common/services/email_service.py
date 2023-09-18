import os

import boto3
from botocore.exceptions import ClientError

# Replace these with your AWS access key ID and secret access key
aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")

# Create an SES client
ses_client = boto3.client('ses', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

# Specify the sender's email address and recipient's email address
sender_email = 'your-sender@example.com'
recipient_email = 'recipient@example.com'

# Specify the email subject and body
subject = 'Hello from Amazon SES'
body_text = 'This is a test email sent using Amazon SES in Python.'
body_html = '<html><body><p>This is a test email sent using <b>Amazon SES</b> in <span style="color:blue;">Python</span>.</p></body></html>'

# Create the email message
message = {
    'Subject': {
        'Data': subject,
    },
    'Body': {
        'Text': {
            'Data': body_text,
        },
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
