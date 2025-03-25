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
SUBJECT = "🚨 Trivy Security Scan Report 🚨"

# Load the Trivy report
ATTACHMENT_PATH = "trivy-report.json"
with open(ATTACHMENT_PATH, "r") as file:
    report = json.load(file)

# Extract vulnerabilities
vuln_cards = []
for result in report.get("Results", []):
    target = result.get("Target", "Unknown Target")

    for vuln in result.get("Vulnerabilities", []):
        severity_color = "#d32f2f" if vuln["Severity"] == "CRITICAL" else "#f57c00"
        vuln_cards.append(f"""
            <div class="vuln-card">
                <p class="severity" style="background: {severity_color};">{vuln["Severity"]}</p>
                <h3>{vuln['VulnerabilityID']}</h3>
                <p><b>Package:</b> {vuln['PkgName']} ({vuln['InstalledVersion']})</p>
                <p><b>Fixed Version:</b> {vuln.get('FixedVersion', 'N/A')}</p>
                <a href="{vuln['PrimaryURL']}" class="link">More Info</a>
            </div>
        """)

# Minimalistic email design
if vuln_cards:
    email_body = f"""
    <html>
        <head>
            <style>
                body {{
                    font-family: 'Arial', sans-serif;
                    background-color: #f9f9f9;
                    color: #333;
                    padding: 20px;
                    text-align: center;
                }}
                h2 {{
                    color: #d32f2f;
                    margin-bottom: 10px;
                }}
                .container {{
                    width: 80%;
                    margin: 0 auto;
                    max-width: 600px;
                    background: #fff;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}
                .vuln-card {{
                    background: #fff;
                    padding: 15px;
                    margin: 15px 0;
                    border-left: 5px solid #d32f2f;
                    border-radius: 5px;
                    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
                }}
                .severity {{
                    color: #fff;
                    padding: 5px;
                    border-radius: 4px;
                    font-size: 12px;
                    text-transform: uppercase;
                    font-weight: bold;
                    display: inline-block;
                    margin-bottom: 5px;
                }}
                .link {{
                    text-decoration: none;
                    color: #0288d1;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>🚨 Security Scan Report 🚨</h2>
                <p>📌 <b>{len(vuln_cards)} Critical/High vulnerabilities found.</b></p>
                {"".join(vuln_cards[:5])}  <!-- Show first 5 vulnerabilities -->
                <hr>
                <p>📎 Full report attached.</p>
            </div>
        </body>
    </html>
    """
else:
    email_body = """
    <html>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
            <h3 style="color:green;">✅ No vulnerabilities found in the latest scan.</h3>
        </body>
    </html>
    """

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
