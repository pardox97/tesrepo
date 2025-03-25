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
SUBJECT = "🚨 Security Vulnerability Assessment Report 🚨"

# Load the Trivy report
ATTACHMENT_PATH = "trivy-report.json"
with open(ATTACHMENT_PATH, "r") as file:
    report = json.load(file)

# Get Current Date
current_date = datetime.now().strftime("%B %d, %Y")
report_id = f"SR-{datetime.now().strftime('%Y-%m-%d')}-001"

# Extract vulnerability data
vuln_details = []
severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
total_vulns = 0

for result in report.get("Results", []):
    target = result.get("Target", "Unknown Target")

    for vuln in result.get("Vulnerabilities", []):
        severity = vuln["Severity"]
        severity_count[severity] = severity_count.get(severity, 0) + 1
        total_vulns += 1

        vuln_details.append(f"""
            <h4>{vuln['Title']}</h4>
            <p><b>Severity:</b> {severity}</p>
            <p><b>CVE ID:</b> {vuln.get('VulnerabilityID', 'N/A')}</p>
            <p><b>Affected Component:</b> {target}</p>
            <p><b>Description:</b> {vuln['Description']}</p>
            <p><b>Recommendation:</b> {vuln.get('FixedVersion', 'Update available' if severity in ['Critical', 'High'] else 'N/A')}</p>
            <p><b>Status:</b> Open</p>
            <hr>
        """)

# Risk Summary Table
risk_summary = f"""
    <table style="width:100%; border-collapse: collapse; text-align: left;">
        <tr style="background:#f4f4f4;">
            <th style="padding: 8px; border-bottom: 2px solid #ddd;">Severity</th>
            <th style="padding: 8px; border-bottom: 2px solid #ddd;">Count</th>
            <th style="padding: 8px; border-bottom: 2px solid #ddd;">Percentage</th>
        </tr>
        <tr><td>🔴 Critical</td><td>{severity_count['Critical']}</td><td>{(severity_count['Critical'] / total_vulns) * 100:.1f}%</td></tr>
        <tr><td>🟠 High</td><td>{severity_count['High']}</td><td>{(severity_count['High'] / total_vulns) * 100:.1f}%</td></tr>
        <tr><td>🟡 Medium</td><td>{severity_count['Medium']}</td><td>{(severity_count['Medium'] / total_vulns) * 100:.1f}%</td></tr>
        <tr><td>🟢 Low</td><td>{severity_count['Low']}</td><td>{(severity_count['Low'] / total_vulns) * 100:.1f}%</td></tr>
    </table>
"""

# Format the email body
email_body = f"""
<html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                color: #333;
                padding: 20px;
            }}
            h2, h3, h4 {{
                color: #d32f2f;
            }}
            .container {{
                max-width: 700px;
                margin: 0 auto;
                padding: 20px;
                background: #fff;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }}
            th, td {{
                padding: 10px;
                border: 1px solid #ddd;
                text-align: left;
            }}
            th {{
                background: #f44336;
                color: white;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Security Report: Vulnerability Assessment</h2>
            <p><b>Date:</b> {current_date}</p>
            <p><b>Prepared by:</b> [Your Name/Organization]</p>
            <p><b>Prepared for:</b> [Client Name/Organization]</p>
            <p><b>Report ID:</b> {report_id}</p>

            <h3>📌 Executive Summary</h3>
            <p>This security report outlines the findings of a vulnerability assessment conducted on [System/Application Name]. The assessment identified {total_vulns} vulnerabilities, ranging from low to critical severity. Immediate remediation is recommended for {severity_count['Critical']} critical vulnerabilities to prevent potential exploitation.</p>

            <h3>🔍 Scope of Assessment</h3>
            <p><b>Target System/Application:</b> [Web Application, Network, etc.]</p>
            <p><b>Environment:</b> [Production, Staging]</p>
            <p><b>Assessment Period:</b> [Start Date] to [End Date]</p>
            <p><b>Tools Used:</b> Trivy, AWS Security Hub</p>
            <p><b>Methodology:</b> OWASP Top 10, Automated Scanning</p>

            <h3>🚨 Vulnerability Findings</h3>
            {''.join(vuln_details[:5])} <!-- Show first 5 vulnerabilities -->

            <h3>📊 Risk Summary</h3>
            {risk_summary}

            <h3>🚀 Next Steps</h3>
            <ul>
                <li>🔹 Apply patches & updates for critical vulnerabilities.</li>
                <li>🔹 Improve security configurations & input validation.</li>
                <li>🔹 Conduct regular security audits.</li>
            </ul>

            <p>📎 <b>Full vulnerability report attached.</b></p>
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
