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
SUBJECT = "🚨 Trivy Vulnerability Scan Report 🚨"

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
        severity_badge = f'<span style="background-color:{severity_color}; color:#fff; padding:5px 10px; border-radius:5px; font-size:12px;">{vuln["Severity"]}</span>'

        vuln_cards.append(f"""
            <div class="card">
                <h3>{vuln['VulnerabilityID']}</h3>
                <p><b>Package:</b> {vuln['PkgName']} ({vuln['InstalledVersion']})</p>
                <p>{severity_badge}</p>
                <p><b>Fixed Version:</b> {vuln.get('FixedVersion', 'N/A')}</p>
                <p class="desc">{vuln['Description']}</p>
                <a href="{vuln['PrimaryURL']}" class="btn">More Info</a>
            </div>
        """)

# Format the email body with modern UI styles
if vuln_cards:
    email_body = f"""
    <html>
        <head>
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap');
                body {{
                    font-family: 'Inter', sans-serif;
                    background-color: #f4f4f4;
                    color: #333;
                    padding: 20px;
                }}
                h2 {{
                    color: #d32f2f;
                    text-align: center;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background: #fff;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}
                .card {{
                    background: #fff;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                }}
                .desc {{
                    font-size: 14px;
                    color: #555;
                }}
                .btn {{
                    display: inline-block;
                    margin-top: 10px;
                    padding: 8px 12px;
                    background: #0288d1;
                    color: #fff;
                    text-decoration: none;
                    border-radius: 5px;
                    font-size: 14px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>🚨 High & Critical Vulnerabilities Found 🚨</h2>
                <p>📌 <b>Total Vulnerabilities Found:</b> {len(vuln_cards)}</p>
                <p>📎 Full report attached.</p>
                {"".join(vuln_cards[:5])}  <!-- Show first 5 vulnerabilities -->
                <hr>
                <h3>🚀 Next Steps</h3>
                <ul>
                    <li>🔹 Upgrade affected packages to the recommended fixed versions.</li>
                    <li>🔹 Investigate if any applications rely on these vulnerable libraries.</li>
                    <li>🔹 Monitor logs for any signs of exploitation.</li>
                </ul>
            </div>
        </body>
    </html>
    """
else:
    email_body = """
    <html>
        <head>
            <style>
                body {{
                    font-family: 'Inter', sans-serif;
                    background-color: #f4f4f4;
                    color: #333;
                    padding: 20px;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background: #fff;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    text-align: center;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h3 style="color:green;">✅ No vulnerabilities found in the latest scan.</h3>
            </div>
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
