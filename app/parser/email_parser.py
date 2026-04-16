"""Utilities for parsing raw email messages into normalized models."""

import logging
import re
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import getaddresses
from html.parser import HTMLParser

from app.ingestor.email_ingestor import IngestedEmail
from app.models.email_models import AnchorLink, ParsedEmail


logger = logging.getLogger(__name__)

TEXT_LINK_PATTERN = re.compile(r"https?://[^\s<>\"]+")
AUTH_RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([A-Za-z0-9_-]+)", re.IGNORECASE)


@dataclass(slots=True)
class _AnchorCandidate:
    """Temporary container used while parsing HTML anchors."""

    href: str
    text_parts: list[str]


class LinkExtractor(HTMLParser):
    """Extract links from HTML anchor tags."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.anchor_links: list[AnchorLink] = []
        self._current_anchor: _AnchorCandidate | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return

        for attr_name, attr_value in attrs:
            if attr_name.lower() == "href" and attr_value:
                href = attr_value.strip()
                self.links.append(href)
                self._current_anchor = _AnchorCandidate(href=href, text_parts=[])
                break

    def handle_data(self, data: str) -> None:
        if self._current_anchor is not None:
            self._current_anchor.text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self._current_anchor is None:
            return

        text = " ".join(part.strip() for part in self._current_anchor.text_parts if part.strip())
        self.anchor_links.append(AnchorLink(href=self._current_anchor.href, text=text))
        self._current_anchor = None


class EmailParser:
    """Parse raw email messages into a normalized internal structure."""

    def parse_emails(self, emails: list[IngestedEmail]) -> list[ParsedEmail]:
        """Parse a list of ingested emails."""
        parsed_emails: list[ParsedEmail] = []

        for email_item in emails:
            parsed_emails.append(self.parse_email(email_item))

        return parsed_emails

    def parse_email(self, email_item: IngestedEmail) -> ParsedEmail:
        """Parse a single ingested email."""
        message = email_item.message
        plain_text_body, html_body = self._extract_bodies(message)
        links, anchor_links = self._extract_links(plain_text_body, html_body)
        authentication_results = self._get_header_value(message, "Authentication-Results")

        spf_result = self._extract_auth_result(authentication_results, "spf")
        dkim_result = self._extract_auth_result(authentication_results, "dkim")
        dmarc_result = self._extract_auth_result(authentication_results, "dmarc")

        return ParsedEmail(
            file_name=email_item.file_name,
            from_address=self._extract_primary_address(message, "From"),
            to_address=self._extract_primary_address(message, "To"),
            subject=self._get_header_value(message, "Subject"),
            date=self._get_header_value(message, "Date"),
            plain_text_body=plain_text_body,
            html_body=html_body,
            links=links,
            anchor_links=anchor_links,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            authentication_results=authentication_results,
        )

    def _extract_bodies(self, message: EmailMessage) -> tuple[str, str]:
        plain_text_parts: list[str] = []
        html_parts: list[str] = []

        try:
            if message.is_multipart():
                for part in message.walk():
                    if part.is_multipart():
                        continue

                    content_disposition = (part.get_content_disposition() or "").lower()
                    if content_disposition == "attachment":
                        continue

                    body = self._safe_get_content(part)
                    if not body:
                        continue

                    content_type = part.get_content_type().lower()
                    if content_type == "text/plain":
                        plain_text_parts.append(body)
                    elif content_type == "text/html":
                        html_parts.append(body)
            else:
                body = self._safe_get_content(message)
                if body:
                    content_type = message.get_content_type().lower()
                    if content_type == "text/html":
                        html_parts.append(body)
                    else:
                        plain_text_parts.append(body)
        except Exception as exc:
            logger.warning("Failed to extract body content: %s", exc)

        return "\n".join(plain_text_parts).strip(), "\n".join(html_parts).strip()

    def _extract_links(self, plain_text_body: str, html_body: str) -> tuple[list[str], list[AnchorLink]]:
        links: list[str] = []
        anchor_links: list[AnchorLink] = []

        for link in TEXT_LINK_PATTERN.findall(plain_text_body):
            if link not in links:
                links.append(link)

        if html_body:
            extractor = LinkExtractor()
            try:
                extractor.feed(html_body)
                extractor.close()
            except Exception as exc:
                logger.warning("Failed to parse HTML links: %s", exc)

            for link in extractor.links:
                if link not in links:
                    links.append(link)

            anchor_links.extend(extractor.anchor_links)

            for link in TEXT_LINK_PATTERN.findall(html_body):
                if link not in links:
                    links.append(link)

        return links, anchor_links

    def _extract_primary_address(self, message: EmailMessage, header_name: str) -> str | None:
        header_value = self._get_header_value(message, header_name)
        if not header_value:
            return None

        addresses = getaddresses([header_value])
        for _, address in addresses:
            cleaned_address = address.strip()
            if cleaned_address:
                return cleaned_address

        return header_value.strip() or None

    def _get_header_value(self, message: EmailMessage, header_name: str) -> str | None:
        try:
            value = message.get(header_name)
        except Exception as exc:
            logger.warning("Failed to read header %s: %s", header_name, exc)
            return None

        if value is None:
            return None

        cleaned_value = str(value).strip()
        return cleaned_value or None

    def _extract_auth_result(self, authentication_results: str | None, mechanism: str) -> str | None:
        if not authentication_results:
            return None

        for match in AUTH_RESULT_PATTERN.finditer(authentication_results):
            if match.group(1).lower() == mechanism.lower():
                return match.group(2).lower()

        return None

    def _safe_get_content(self, part: EmailMessage) -> str:
        try:
            content = part.get_content()
        except Exception as exc:
            logger.warning("Failed to decode email part: %s", exc)
            return ""

        if isinstance(content, str):
            return content

        return ""
