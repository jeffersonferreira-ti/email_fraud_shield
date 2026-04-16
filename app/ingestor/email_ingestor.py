"""Utilities for loading raw email files from disk."""

import logging
from dataclasses import dataclass
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class IngestedEmail:
    """Container for a raw email and its source file name."""

    file_name: str
    message: EmailMessage


class EmailIngestor:
    """Load raw `.eml` files from a local directory."""

    def __init__(self) -> None:
        self._parser = BytesParser(policy=default)

    def load_from_directory(self, directory: str | Path) -> tuple[list[IngestedEmail], int]:
        """Load all readable `.eml` files from a directory."""
        directory_path = Path(directory)
        loaded_emails: list[IngestedEmail] = []
        failed_count = 0

        if not directory_path.exists():
            logger.warning("Directory does not exist: %s", directory_path)
            logger.info("Found 0 .eml files in %s", directory_path)
            logger.info("Successfully loaded 0 files")
            logger.info("Failed to load 0 files")
            return loaded_emails, failed_count

        if not directory_path.is_dir():
            logger.warning("Path is not a directory: %s", directory_path)
            logger.info("Found 0 .eml files in %s", directory_path)
            logger.info("Successfully loaded 0 files")
            logger.info("Failed to load 0 files")
            return loaded_emails, failed_count

        eml_files = sorted(
            path for path in directory_path.iterdir() if path.is_file() and path.suffix.lower() == ".eml"
        )

        logger.info("Found %d .eml files in %s", len(eml_files), directory_path)

        for file_path in eml_files:
            try:
                with file_path.open("rb") as email_file:
                    message = self._parser.parse(email_file)
            except (OSError, ValueError) as exc:
                failed_count += 1
                logger.warning("Failed to load %s: %s", file_path.name, exc)
                continue

            loaded_emails.append(
                IngestedEmail(
                    file_name=file_path.name,
                    message=message,
                )
            )

        logger.info("Successfully loaded %d files", len(loaded_emails))
        logger.info("Failed to load %d files", failed_count)

        return loaded_emails, failed_count
