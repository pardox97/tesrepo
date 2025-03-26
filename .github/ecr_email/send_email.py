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
        <hr>
        <h3>🔹 {vuln['VulnerabilityID']}</h3>
        <ul>
            <li><b>Package:</b> {vuln['PkgName']} ({vuln['InstalledVersion']})</li>
            <li><b>⚠️ Severity:</b> <b>{vuln['Severity']}</b></li>
            <li><b>✅ Fixed Version:</b> {vuln.get('FixedVersion', 'N/A')}</li>
            <li><b>📝 Description:</b> {vuln['Description']}</li>
            <li><b>🔗 More Info:</b> <a href="{vuln['PrimaryURL']}">{vuln['PrimaryURL']}</a></li>
            <li><b>🛠️ Affected Target:</b> {target}</li>
        </ul>
        """)

# Format the email body with HTML
if vuln_summary:
    email_body = f"""
    <html>
        <body>
            <h2>🚨 Critical / High Vulnerabilities Found 🚨</h2>
            <p>📌 <b>Total Vulnerabilities Found:</b> {len(vuln_summary)}</p>
            <p>📎 Full report attached.</p>
            {"".join(vuln_summary[:5])}  <!-- Show first 5 vulnerabilities -->
            <hr>
            <h3>🚀 Next Steps</h3>
            <ul>
                <li>🔹 Upgrade affected packages to the recommended fixed versions.</li>
                <li>🔹 Investigate if any applications rely on these vulnerable libraries.</li>
                <li>🔹 Monitor logs for any signs of exploitation.</li>
            </ul>
        </body>
    </html>
    """
else:
    email_body = "<h3>✅ No vulnerabilities found in the latest scan.</h3>"

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