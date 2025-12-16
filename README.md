# AWS Security Scanner

A Python-based security scanning tool for AWS environments that identifies potential security vulnerabilities and misconfigurations in your AWS resources.

## Features

- Scans AWS resources for security vulnerabilities
- Identifies misconfigurations and security best practice violations
- Generates detailed security findings in JSON format
- Easy to configure and extend

## Prerequisites

- Python 3.6 or higher
- AWS CLI configured with appropriate credentials
- Required Python packages (install using `pip install -r requirements.txt`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/srii18/DeepArmor_Assignment.git
   cd DeepArmor_Assignment
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

1. Ensure your AWS credentials are properly configured using AWS CLI:
   ```bash
   aws configure
   ```

2. Copy the example environment file and update it with your configuration:
   ```bash
   cp example.env .env
   ```
   Then edit the `.env` file with your AWS credentials and desired settings.

3. The `.env` file should never be committed to version control. It's already included in `.gitignore` for security.

4. The `example.env` file contains all available configuration options with documentation.

## Usage

Run the AWS Security Scanner:
```bash
python aws_security_scanner.py
```

## Output

The scanner generates a `security_findings.json` file containing detailed security findings, including:
- Resource details
- Security issues identified
- Severity levels
- Recommendations for remediation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.
