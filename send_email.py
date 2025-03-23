import boto3
import os
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# AWS SES Configuration
AWS_REGION = os.getenv("AWS_REGION")
SENDER = "cardosomelford@gmail.com"  # Must be a verified email in AWS SES
RECIPIENT =  "cardosomelford@gmail.com"  # Must be a verified email in AWS SES
SUBJECT = "Vulnerability Scan Report"

# Read the Trivy report
ATTACHMENT_PATH = "trivy-report.json"
with open(ATTACHMENT_PATH, "rb") as attachment:
    attachment_part = MIMEBase("application", "octet-stream")
    attachment_part.set_payload(attachment.read())

# Encode file to Base64
encoders.encode_base64(attachment_part)
attachment_part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(ATTACHMENT_PATH)}")

# Create email message
msg = MIMEMultipart()
msg["From"] = SENDER
msg["To"] = RECIPIENT
msg["Subject"] = SUBJECT

# Add email body
body = "Please find the attached vulnerability scan report."
msg.attach(MIMEText(body, "plain"))
msg.attach(attachment_part)

# Send email using AWS SES
ses_client = boto3.client(
    "ses",
    region_name=AWS_REGION,
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
)

response = ses_client.send_raw_email(Source=SENDER, Destinations=[RECIPIENT], RawMessage={"Data": msg.as_string()})
print("✅ Email sent successfully! Message ID:", response["MessageId"])
