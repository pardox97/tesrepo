import boto3
import os
import json
import base64
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# AWS SES Configuration
AWS_REGION = os.getenv("AWS_REGION")
SENDER = "cardozomelford@gmail.com"  # Must be verified in AWS SES
RECIPIENT = "cardozomelford@gmail.com"  # Must be verified in AWS SES
SUBJECT = "🚨 Security Vulnerability Report 🚨"

# Load the Trivy report
ATTACHMENT_PATH = "trivy-report.json"
with open(ATTACHMENT_PATH, "r") as file:
    report = json.load(file)

# Get Current Date
current_date = datetime.now().strftime("%B %d, %Y")

# Extract vulnerabilities
vuln_rows = []
total_vulnerabilities = 0

for result in report.get("Results", []):
    target = result.get("Target", "Unknown Target")

    for vuln in result.get("Vulnerabilities", []):
        severity_class = {
            "CRITICAL": "severity-critical",
            "HIGH": "severity-high",
            "MEDIUM": "severity-medium",
            "LOW": "severity-low",
        }.get(vuln["Severity"].upper(), "")

        vuln_rows.append(f"""
            <tr>
                <td>{total_vulnerabilities + 1}</td>
                <td>{vuln['Title']}</td>
                <td>{vuln['Description']}</td>
                <td class="{severity_class}">{vuln["Severity"]}</td>
                <td>Open</td>
            </tr>
        """)
        total_vulnerabilities += 1

# Read the HTML template and insert values
with open("email_template.html", "r") as template_file:
    email_body = template_file.read()
    email_body = email_body.replace("{{DATE}}", current_date)
    email_body = email_body.replace("{{TOTAL_VULNERABILITIES}}", str(total_vulnerabilities))
    email_body = email_body.replace("{{VULNERABILITY_ROWS}}", "".join(vuln_rows))

# Create email message
msg = MIMEMultipart()
msg["From"] = SENDER
msg["To"] = RECIPIENT
msg["Subject"] = SUBJECT

# Add HTML body
msg.attach(MIMEText(email_body, "html"))

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
