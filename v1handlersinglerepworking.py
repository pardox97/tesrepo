import json
import requests
import os

GITHUB_REPO = "pardox97/tesrepo" 
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # Store this in Lambda environment variables
GITHUB_WORKFLOW = "image-scan.yml"  # Change this to match your workflow file

def lambda_handler(event, context):
    print("Received event:", json.dumps(event, indent=2))

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}"
    }
    
    url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/workflows/{GITHUB_WORKFLOW}/dispatches"
    
    payload = {
        "ref": "main"  # Change if needed
    }

    response = requests.post(url, headers=headers, json=payload)

    print(f"GitHub Response: {response.status_code} - {response.text}")

    return {
        "statusCode": response.status_code,
        "body": response.text
    }
