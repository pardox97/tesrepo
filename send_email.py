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
vuln_summary = []
for result in report.get("Results", []):
    target = result.get("Target", "Unknown Target")
    
    for vuln in result.get("Vulnerabilities", []):
        severity_color = "🔴" if vuln["Severity"] == "CRITICAL" else "🟠"
        vuln_summary.append(f"""
            <tr>
                <td>{severity_color} <b>{vuln['VulnerabilityID']}</b></td>
                <td>{vuln['PkgName']} ({vuln['InstalledVersion']})</td>
                <td style="color:{'red' if vuln['Severity'] == 'CRITICAL' else 'orange'};"><b>{vuln['Severity']}</b></td>
                <td>{vuln.get('FixedVersion', 'N/A')}</td>
                <td>{vuln['Description']}</td>
                <td><a href="{vuln['PrimaryURL']}">More Info</a></td>
            </tr>
        """)

# Format the email body with enhanced HTML & CSS
if vuln_summary:
    email_body = f"""
    <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                }}
                h2 {{
                    color: #d32f2f;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                th, td {{
                    padding: 10px;
                    border: 1px solid #ddd;
                    text-align: left;
                }}
                th {{
                    background-color: #f44336;
                    color: white;
                }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
            </style>
        </head>
        <body>
            <h2>🚨 High & Critical Vulnerabilities Found 🚨</h2>
            <p>📌 <b>Total Vulnerabilities Found:</b> {len(vuln_summary)}</p>
            <p>📎 Full report attached.</p>

            <table>
                <tr>
                    <th>CVE ID</th>
                    <th>Package</th>
                    <th>Severity</th>
                    <th>Fixed Version</th>
                    <th>Description</th>
                    <th>More Info</th>
                </tr>
                {"".join(vuln_summary[:5])}  <!-- Show first 5 vulnerabilities -->
            </table>

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
    email_body = """
    <html>
        <body>
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
