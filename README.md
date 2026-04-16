# Email Fraud Shield

Email Fraud Shield is a security-focused Python application that analyzes `.eml` email files to help identify phishing attempts and suspicious patterns.

## MVP Scope

This first milestone includes only the initial project setup:

- modular folder structure
- clean entry point
- basic configuration module
- data directories for samples and generated output

No business logic, parsing, detection rules, or integrations are implemented yet.

## Project Structure

```text
email_fraud_shield/
├── app/
│   ├── analyzer/
│   ├── alerts/
│   ├── ingestor/
│   ├── llm/
│   ├── models/
│   ├── parser/
│   └── reporting/
├── data/
│   ├── output/
│   └── samples/
├── config.py
├── main.py
├── README.md
└── requirements.txt
```

## Requirements

- Python 3.10+

## How To Run

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the application:

```bash
python main.py
```

The current entry point only confirms that the project is configured correctly.
