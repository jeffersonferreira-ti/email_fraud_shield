"""Score aggregation for heuristic email analysis."""

from __future__ import annotations

from app.models.email_models import HeuristicFinding


class RiskScorer:
    """Calculate total score from triggered heuristic findings."""

    def score(self, findings: list[HeuristicFinding]) -> int:
        """Return the total score for a set of findings."""
        return sum(max(0, finding.score) for finding in findings)
