"""Normalized email models used by the application."""

from dataclasses import dataclass, field
from typing import Any


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


@dataclass(slots=True)
class HeuristicFinding:
    """Single heuristic finding generated during analysis."""

    rule_name: str
    description: str
    severity: str
    score: int
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScoredEmail:
    """Parsed email enriched with heuristic analysis results."""

    parsed_email: ParsedEmail
    findings: list[HeuristicFinding] = field(default_factory=list)
    total_score: int = 0
    classification: str = "LEGITIMO"
