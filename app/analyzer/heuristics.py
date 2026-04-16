"""Heuristic rules for email fraud analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app.models.email_models import HeuristicFinding, ParsedEmail


@dataclass(slots=True)
class RuleContext:
    """Normalized text and sender context reused across heuristics."""

    combined_text: str
    sender_local_part: str
    sender_domain: str


class HeuristicAnalyzer:
    """Evaluate parsed emails against a small set of phishing heuristics."""

    _AUTH_RESULT_SCORES = {
        "fail": 14,
        "softfail": 10,
        "temperror": 8,
        "permerror": 10,
        "neutral": 6,
        "none": 6,
        "missing": 5,
    }
    _SUSPICIOUS_SUBJECT_OR_BODY_TERMS = (
        "urgente",
        "immediately",
        "imediatamente",
        "agora",
        "immediate action",
        "action required",
        "urgent",
        "30 minutos",
        "limited time",
        "as soon as possible",
    )
    _SENSITIVE_INFO_TERMS = (
        "senha",
        "password",
        "security code",
        "codigo de seguranca",
        "credential",
        "credentials",
        "pin",
        "token",
        "one-time code",
        "verification code",
        "passcode",
    )
    _ACCOUNT_PRESSURE_TERMS = (
        "bloqueada",
        "blocked",
        "encerrada",
        "suspended",
        "suspensa",
        "temporary restrictions",
        "verify your account",
        "confirm your account",
        "confirme seus dados",
        "desbloquear",
    )
    _SUSPICIOUS_SENDER_TOKENS = (
        "verify",
        "verification",
        "security",
        "secure",
        "support",
        "update",
        "alert",
        "check",
        "login",
    )
    _TRUSTED_DOMAINS = {
        "github.com",
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
    }

    def analyze(self, email: ParsedEmail) -> list[HeuristicFinding]:
        """Run all heuristic rules and return triggered findings."""
        context = self._build_context(email)
        findings: list[HeuristicFinding] = []

        for rule in (
            self._check_authentication,
            self._check_urgency_language,
            self._check_sensitive_information_request,
            self._check_suspicious_links,
            self._check_suspicious_sender_patterns,
            self._check_account_pressure_language,
        ):
            finding = rule(email, context)
            if finding is not None:
                findings.append(finding)

        return findings

    def _build_context(self, email: ParsedEmail) -> RuleContext:
        combined_text = " ".join(
            part for part in (email.subject or "", email.plain_text_body, email.html_body) if part
        ).lower()
        sender_local_part = ""
        sender_domain = ""

        if email.from_address and "@" in email.from_address:
            sender_local_part, sender_domain = email.from_address.lower().split("@", 1)

        return RuleContext(
            combined_text=combined_text,
            sender_local_part=sender_local_part,
            sender_domain=sender_domain,
        )

    def _check_authentication(
        self, email: ParsedEmail, context: RuleContext
    ) -> HeuristicFinding | None:
        del context
        failing_mechanisms: list[str] = []
        suspicious_mechanisms: list[str] = []
        total_score = 0

        for name, result in (
            ("spf", email.spf_result),
            ("dkim", email.dkim_result),
            ("dmarc", email.dmarc_result),
        ):
            normalized = (result or "").strip().lower()
            if not normalized:
                suspicious_mechanisms.append(f"{name}=missing")
                total_score += self._AUTH_RESULT_SCORES["missing"]
            elif normalized in {"pass", "bestguesspass"}:
                continue
            elif normalized in self._AUTH_RESULT_SCORES:
                failing_mechanisms.append(f"{name}={normalized}")
                total_score += self._AUTH_RESULT_SCORES[normalized]
            else:
                suspicious_mechanisms.append(f"{name}={normalized}")
                total_score += 6

        if not failing_mechanisms and not suspicious_mechanisms:
            return None

        score = min(40, total_score)
        severity = "high" if failing_mechanisms else "medium"
        evidence = {
            "from_address": email.from_address,
            "authentication_results": email.authentication_results,
            "failing_mechanisms": failing_mechanisms,
            "suspicious_mechanisms": suspicious_mechanisms,
        }

        return HeuristicFinding(
            rule_name="authentication_failures",
            description="SPF, DKIM, or DMARC results indicate failure or suspicious authentication state.",
            severity=severity,
            score=score,
            evidence=evidence,
        )

    def _check_urgency_language(
        self, email: ParsedEmail, context: RuleContext
    ) -> HeuristicFinding | None:
        matches = self._collect_matches(context.combined_text, self._SUSPICIOUS_SUBJECT_OR_BODY_TERMS)
        if not matches:
            return None

        return HeuristicFinding(
            rule_name="urgency_language",
            description="The message uses urgency language commonly seen in phishing attempts.",
            severity="medium",
            score=12,
            evidence={
                "from_address": email.from_address,
                "subject": email.subject,
                "matched_terms": matches,
            },
        )

    def _check_sensitive_information_request(
        self, email: ParsedEmail, context: RuleContext
    ) -> HeuristicFinding | None:
        matches = self._collect_matches(context.combined_text, self._SENSITIVE_INFO_TERMS)
        if not matches:
            return None

        return HeuristicFinding(
            rule_name="sensitive_information_request",
            description="The message appears to request passwords, codes, or account credentials.",
            severity="high",
            score=20,
            evidence={
                "from_address": email.from_address,
                "subject": email.subject,
                "matched_terms": matches,
            },
        )

    def _check_suspicious_links(
        self, email: ParsedEmail, context: RuleContext
    ) -> HeuristicFinding | None:
        del context
        flagged_links: list[dict[str, str]] = []

        for link in email.links:
            parsed = urlparse(link)
            scheme = parsed.scheme.lower()
            host = parsed.netloc.lower()
            reasons: list[str] = []

            if scheme != "https":
                reasons.append("non_https")

            if not host:
                reasons.append("missing_host")
            elif self._looks_suspicious_host(host):
                reasons.append("suspicious_domain_pattern")

            if reasons:
                flagged_links.append({"url": link, "reasons": ", ".join(reasons)})

        if not flagged_links:
            return None

        high_risk = any("non_https" in item["reasons"] for item in flagged_links)
        return HeuristicFinding(
            rule_name="suspicious_links",
            description="The message contains suspicious links or links that do not use HTTPS.",
            severity="high" if high_risk else "medium",
            score=min(25, 10 + (len(flagged_links) - 1) * 5),
            evidence={
                "from_address": email.from_address,
                "flagged_links": flagged_links,
            },
        )

    def _check_suspicious_sender_patterns(
        self, email: ParsedEmail, context: RuleContext
    ) -> HeuristicFinding | None:
        if not context.sender_domain:
            return None

        reasons: list[str] = []
        if self._looks_suspicious_host(context.sender_domain):
            reasons.append("sender_domain_pattern")

        if any(token in context.sender_local_part for token in self._SUSPICIOUS_SENDER_TOKENS):
            reasons.append("sender_local_part_keyword")

        if context.sender_domain.count("-") >= 2:
            reasons.append("excessive_hyphenation")

        if reasons and context.sender_domain in self._TRUSTED_DOMAINS:
            reasons = [reason for reason in reasons if reason != "sender_domain_pattern"]

        if not reasons:
            return None

        return HeuristicFinding(
            rule_name="suspicious_sender_patterns",
            description="The sender address uses patterns often associated with spoofing or phishing domains.",
            severity="medium",
            score=15,
            evidence={
                "from_address": email.from_address,
                "sender_domain": context.sender_domain,
                "reasons": reasons,
            },
        )

    def _check_account_pressure_language(
        self, email: ParsedEmail, context: RuleContext
    ) -> HeuristicFinding | None:
        matches = self._collect_matches(context.combined_text, self._ACCOUNT_PRESSURE_TERMS)
        if not matches:
            return None

        return HeuristicFinding(
            rule_name="account_blocking_or_forced_verification",
            description="The message pressures the recipient with account blocking or forced verification language.",
            severity="high",
            score=18,
            evidence={
                "from_address": email.from_address,
                "subject": email.subject,
                "matched_terms": matches,
            },
        )

    def _collect_matches(self, text: str, terms: tuple[str, ...]) -> list[str]:
        matches = [term for term in terms if term in text]
        return sorted(set(matches))

    def _looks_suspicious_host(self, host: str) -> bool:
        normalized_host = host.lower().strip(".")
        if not normalized_host:
            return False

        if normalized_host in self._TRUSTED_DOMAINS:
            return False

        labels = [label for label in normalized_host.split(".") if label]
        base_domain = ".".join(labels[-2:]) if len(labels) >= 2 else normalized_host

        suspicious_token_count = sum(
            1 for token in self._SUSPICIOUS_SENDER_TOKENS if token in normalized_host
        )
        has_mixed_brand_like_terms = bool(re.search(r"(bank|account|login|secure|verify)", normalized_host))

        return (
            normalized_host.count("-") >= 2
            or suspicious_token_count >= 2
            or (has_mixed_brand_like_terms and base_domain not in self._TRUSTED_DOMAINS)
        )
