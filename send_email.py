import boto3
import os
import json
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# AWS SES Configuration
AWS_REGION = os.getenv("AWS_REGION")
SENDER = "cardozomelford@gmail.com"  # Must be verified in AWS SES
RECIPIENT = "cardozomelford@gmail.com"  # Must be verified in AWS SES
SUBJECT = "🚨 Security Vulnerability Assessment Report 🚨"

# Load the Trivy report
ATTACHMENT_PATH = "trivy-report.json"
with open(ATTACHMENT_PATH, "r") as file:
    report = json.load(file)

# Extract vulnerabilities
vuln_summary = []
for result in report.get("Results", []):
    target = result.get("Target", "Unknown Target")
    
    for vuln in result.get("Vulnerabilities", []):
        vuln_summary.append(f"""
        **CVE ID**: {vuln['VulnerabilityID']}
        **Package**: {vuln['PkgName']} ({vuln['InstalledVersion']})
        **Severity**: {vuln['Severity']}
        **Fixed Version**: {vuln.get('FixedVersion', 'N/A')}
        **Description**: {vuln['Description']}
        **More Info**: {vuln['PrimaryURL']}
        **Affected Target**: {target}
        """)

# Format the email body
if vuln_summary:
    email_body = "**Summary of High & Critical Vulnerabilities Found:**\n\n" + "\n\n".join(vuln_summary[:5])  # Limit to first 5 for brevity
    email_body += f"\n\n📌 **Total Vulnerabilities Found**: {len(vuln_summary)}"
    email_body += "\n\n📎 Full report attached."
else:
    email_body = "✅ No vulnerabilities found in the latest scan."

# Create email message
msg = MIMEMultipart()
msg["From"] = SENDER
msg["To"] = RECIPIENT
msg["Subject"] = SUBJECT

# Add email body
msg.attach(MIMEText(email_body, "plain"))

# Attach the full Trivy report
with open(ATTACHMENT_PATH, "rb") as attachment:
    attachment_part = MIMEBase("application", "octet-stream")
    attachment_part.set_payload(attachment.read())
encoders.encode_base64(attachment_part)
attachment_part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(ATTACHMENT_PATH)}")
msg.attach(attachment_part)

# Send email using AWS SES
ses_client = boto3.client(
    "ses",
    region_name=AWS_REGION,
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
)

response = ses_client.send_raw_email(
    Source=SENDER, Destinations=[RECIPIENT], RawMessage={"Data": msg.as_string()}
)

print("✅ Email sent successfully! Message ID:", response["MessageId"])import boto3
import os
import json
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# AWS SES Configuration
AWS_REGION = os.getenv("AWS_REGION")
SENDER = "cardozomelford@gmail.com"  # Must be verified in AWS SES
RECIPIENT = "cardozomelford@gmail.com"  # Must be verified in AWS SES
SUBJECT = "🚨 Trivy Vulnerability Scan Report 🚨"

# Load the Trivy report
ATTACHMENT_PATH = "trivy-report.json"
with open(ATTACHMENT_PATH, "r") as file:
    report = json.load(file)

# Extract vulnerabilities
vuln_summary = []
for result in report.get("Results", []):
    target = result.get("Target", "Unknown Target")
    
    for vuln in result.get("Vulnerabilities", []):
        vuln_summary.append(f"""
        **CVE ID**: {vuln['VulnerabilityID']}
        **Package**: {vuln['PkgName']} ({vuln['InstalledVersion']})
        **Severity**: {vuln['Severity']}
        **Fixed Version**: {vuln.get('FixedVersion', 'N/A')}
        **Description**: {vuln['Description']}
        **More Info**: {vuln['PrimaryURL']}
        **Affected Target**: {target}
        """)

# Format the email body
if vuln_summary:
    email_body = "**Summary of High & Critical Vulnerabilities Found:**\n\n" + "\n\n".join(vuln_summary[:5])  # Limit to first 5 for brevity
    email_body += f"\n\n📌 **Total Vulnerabilities Found**: {len(vuln_summary)}"
    email_body += "\n\n📎 Full report attached."
else:
    email_body = "✅ No vulnerabilities found in the latest scan."

# Create email message
msg = MIMEMultipart()
msg["From"] = SENDER
msg["To"] = RECIPIENT
msg["Subject"] = SUBJECT

# Add email body
msg.attach(MIMEText(email_body, "plain"))

# Attach the full Trivy report
with open(ATTACHMENT_PATH, "rb") as attachment:
    attachment_part = MIMEBase("application", "octet-stream")
    attachment_part.set_payload(attachment.read())
encoders.encode_base64(attachment_part)
attachment_part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(ATTACHMENT_PATH)}")
msg.attach(attachment_part)

# Send email using AWS SES
ses_client = boto3.client(
    "ses",
    region_name=AWS_REGION,
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
)

response = ses_client.send_raw_email(
    Source=SENDER, Destinations=[RECIPIENT], RawMessage={"Data": msg.as_string()}
)

print("✅ Email sent successfully! Message ID:", response["MessageId"])