import json
import requests
import pandas as pd
from transformers import pipeline

# Example SBOM (Software Bill of Materials) data
sbom_data = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.2",
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "version": 1,
    "metadata": {
        "timestamp": "2021-01-10T14:00:00Z",
        "tools": [
            {
                "vendor": "CycloneDX",
                "name": "CycloneDX Python",
                "version": "1.0.0"
            }
        ],
        "component": {
            "type": "application",
            "name": "AwesomeApp",
            "version": "1.0.0",
            "purl": "pkg:generic/awesomeapp@1.0.0"
        }
    },
    "components": [
        {
            "type": "library",
            "name": "LibA",
            "version": "1.2.3",
            "purl": "pkg:generic/liba@1.2.3",
            "licenses": [
                {
                    "license": {
                        "id": "MIT"
                    }
                }
            ]
        },
        {
            "type": "library",
            "name": "LibB",
            "version": "4.5.6",
            "purl": "pkg:generic/libb@4.5.6",
            "licenses": [
                {
                    "license": {
                        "id": "MIT"
                    }
                }
            ]
        }
    ]
}

# Function to validate SBOM compliance for FDA requirements
def validate_sbom_with_fda_requirements(sbom, fda_requirements):
    validator = pipeline('zero-shot-classification', model='facebook/bart-large-mnli')
    compliance_issues = []

    for component in sbom.get('components', []):
        for license_info in component.get('licenses', []):
            license_id = license_info.get('license', {}).get('id', '')
            result = validator(license_id, candidate_labels=["valid license", "invalid license"])
            if 'invalid license' in result['labels'] and result['scores'][result['labels'].index('invalid license')] > 0.5:
                compliance_issues.append({
                    'component': component['name'],
                    'requirement': 'License compliance',
                    'license': license_id,
                    'score': result['scores'][result['labels'].index('invalid license')]
                })

        for requirement in fda_requirements:
            result = validator(component['name'], candidate_labels=requirement)
            if 'non-compliant' in result['labels']:
                compliance_issues.append({
                    'component': component['name'],
                    'requirement': requirement,
                    'score': result['scores'][0]
                })

    return compliance_issues

# FDA requirements list
fda_requirements = ["Component identification transparency", "License compliance", "Vulnerability management"]

# Call validation function and get compliance issues
compliance_issues = validate_sbom_with_fda_requirements(sbom_data, fda_requirements)

# Display compliance issues
if compliance_issues:
    print("Compliance issues found:")
    df_issues = pd.DataFrame(compliance_issues)
    print(df_issues)
else:
    print("SBOM is fully compliant with FDA requirements.")

# Function to generate compliance report
def generate_compliance_report(issues, compliant=True):
    report = {
        "status": "Compliant" if compliant else "Non-Compliant",
        "issues": issues
    }
    return report

# Function to notify the compliance team
def notify_compliance_team(report):
    webhook_url = "https://hooks.slack.com/services/your-webhook-url"
    message = {
        "text": f"Compliance Report: {report['status']}",
        "attachments": [
            {"text": json.dumps(report['issues'], indent=2)}
        ]
    }
    requests.post(webhook_url, data=json.dumps(message))

# Generate and send compliance report
report = generate_compliance_report(compliance_issues, compliant=not bool(compliance_issues))
notify_compliance_team(report)

# Handle compliance check results
if compliance_issues:
    raise Exception("SBOM validation failed, compliance issues found")
else:
    print("SBOM validation passed, all components are compliant")