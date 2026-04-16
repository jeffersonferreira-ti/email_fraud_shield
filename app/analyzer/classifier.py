"""Classification thresholds for analyzed emails."""

from __future__ import annotations


class RiskClassifier:
    """Map a total score to a final risk classification."""

    def classify(self, total_score: int) -> str:
        """Return the final classification label for a score."""
        if total_score <= 19:
            return "LEGITIMO"
        if total_score <= 49:
            return "SUSPEITO"
        if total_score <= 79:
            return "PHISHING_PROVAVEL"
        return "ALTO_RISCO"
