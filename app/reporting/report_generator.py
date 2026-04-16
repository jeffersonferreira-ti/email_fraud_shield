"""JSON report generation for analyzed emails."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from app.models.email_models import HeuristicFinding, ParsedEmail, ScoredEmail


class ReportGenerator:
    """Generate a JSON report for analyzed emails."""

    def generate(self, results: list[ScoredEmail], output_file: str | Path) -> Path:
        """Write a human-readable JSON report and return its path."""
        report_path = Path(output_file)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_emails": len(results),
            "results": [self._serialize_result(result) for result in results],
        }

        report_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return report_path

    def _serialize_result(self, result: ScoredEmail) -> dict[str, object]:
        parsed_email = result.parsed_email
        sender = parsed_email.from_address or "Unknown sender"

        return {
            "file_name": parsed_email.file_name,
            "sender": sender,
            "subject": parsed_email.subject or "No subject",
            "total_score": result.total_score,
            "classification": result.classification,
            "links": list(parsed_email.links),
            "authentication": self._build_authentication_summary(parsed_email),
            "triggered_rules": [self._serialize_finding(finding) for finding in result.findings],
        }

    def _build_authentication_summary(self, email: ParsedEmail) -> dict[str, str] | None:
        authentication = {
            "spf": email.spf_result,
            "dkim": email.dkim_result,
            "dmarc": email.dmarc_result,
        }
        populated = {key: value for key, value in authentication.items() if value}
        return populated or None

    def _serialize_finding(self, finding: HeuristicFinding) -> dict[str, object]:
        finding_data = asdict(finding)
        return {
            "rule_name": finding_data["rule_name"],
            "severity": finding_data["severity"],
            "score": finding_data["score"],
            "description": finding_data["description"],
            "evidence": finding_data["evidence"],
        }
