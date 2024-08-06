# Project: FDA Compliance Validation for SBOM

## Overview

This project aims to validate the compliance of Software Bill of Materials (SBOM) with FDA requirements. It uses zero-shot classification models from the transformers library to check for license compliance and other regulatory requirements of software components in an application. The project also includes reporting and notification features to aid compliance teams in identifying and addressing issues.

## Key Features

- **SBOM Validation**: Checks software components for compliance with FDA requirements.
- **Zero-Shot Classification**: Uses pre-trained models to classify licenses and component compliance without additional training.
- **Compliance Reporting**: Generates reports on compliance status, highlighting any issues found.
- **Slack Notification**: Sends compliance reports and alerts to a predefined Slack channel.

## Usage

1. **Install Dependencies**: Ensure you have the necessary dependencies installed.
    ```sh
    pip install pandas requests transformers
    ```
2. **Run Validation**: Execute the provided script to perform SBOM validation.

3. **Check Reports**: Review generated reports and Slack notifications for compliance status and issues.
