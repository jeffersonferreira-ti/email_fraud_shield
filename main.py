"""Application entry point."""

import logging

from app.ingestor.email_ingestor import EmailIngestor
from app.parser.email_parser import EmailParser
from config import settings


def configure_logging() -> None:
    """Set up basic application logging for the MVP."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def main() -> None:
    """Start the application, load emails, and parse them."""
    configure_logging()

    ingestor = EmailIngestor()
    ingested_emails, failed_count = ingestor.load_from_directory(settings.samples_dir)
    parser = EmailParser()
    parsed_emails = parser.parse_emails(ingested_emails)

    print(f"Loaded {len(parsed_emails)} emails ({failed_count} failed)")

    for email in parsed_emails:
        sender = email.from_address or "Unknown sender"
        subject = email.subject or "No subject"
        print(
            f"- {email.file_name} | sender: {sender} | subject: {subject} | links: {len(email.links)}"
        )


if __name__ == "__main__":
    main()
