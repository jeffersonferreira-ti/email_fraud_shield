"""Normalized email models used by the application."""

from dataclasses import dataclass, field


@dataclass(slots=True)
class ParsedEmail:
    """Normalized representation of a parsed email."""

    file_name: str
    from_address: str | None = None
    to_address: str | None = None
    subject: str | None = None
    date: str | None = None
    plain_text_body: str = ""
    html_body: str = ""
    links: list[str] = field(default_factory=list)
    spf_result: str | None = None
    dkim_result: str | None = None
    dmarc_result: str | None = None
    authentication_results: str | None = None
