"""Application entry point."""

import argparse
import logging
import sys
from pathlib import Path

from app.analyzer import HeuristicAnalyzer, RiskClassifier, RiskScorer
from app.ingestor.email_ingestor import EmailIngestor
from app.models.email_models import ScoredEmail
from app.parser.email_parser import EmailParser
from app.reporting import ReportGenerator
from config import settings


def configure_logging() -> None:
    """Set up basic application logging for the MVP."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(description="Analyze .eml files for phishing indicators.")
    parser.add_argument(
        "--source",
        type=Path,
        default=settings.samples_dir,
        help="Input directory containing .eml files. Defaults to data/samples.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=settings.output_file,
        help="Output JSON file path. Defaults to data/output/analysis_report.json.",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a compact execution summary after processing.",
    )
    return parser


def validate_source_directory(source_dir: Path) -> None:
    """Validate that the source directory exists and is a directory."""
    if not source_dir.exists():
        raise ValueError(f"Source directory does not exist: {source_dir}")
    if not source_dir.is_dir():
        raise ValueError(f"Source path is not a directory: {source_dir}")


def validate_output_path(output_file: Path) -> None:
    """Validate that the output path can be treated as a JSON file path."""
    if output_file.exists() and output_file.is_dir():
        raise ValueError(f"Output path points to a directory, not a file: {output_file}")
    if output_file.name in {"", ".", ".."}:
        raise ValueError(f"Output path is invalid: {output_file}")


def print_email_details(result: ScoredEmail) -> None:
    """Print a readable analysis summary for one email."""
    email = result.parsed_email
    sender = email.from_address or "Unknown sender"
    subject = email.subject or "No subject"

    print()
    print(f"File: {email.file_name}")
    print(f"Sender: {sender}")
    print(f"Subject: {subject}")
    print(f"Total score: {result.total_score}")
    print(f"Classification: {result.classification}")
    print("Triggered rules:")

    if not result.findings:
        print("  - none")
        return

    for finding in result.findings:
        print(
            "  - "
            f"{finding.rule_name} "
            f"[severity={finding.severity}, score={finding.score}] "
            f"{finding.description}"
        )


def print_compact_summary(results: list[ScoredEmail]) -> None:
    """Print a compact execution summary grouped by classification."""
    counts: dict[str, int] = {}
    for result in results:
        counts[result.classification] = counts.get(result.classification, 0) + 1

    summary_parts = [f"{classification}={count}" for classification, count in sorted(counts.items())]
    summary_text = ", ".join(summary_parts) if summary_parts else "no emails analyzed"
    print()
    print(f"Summary: {summary_text}")


def main(argv: list[str] | None = None) -> int:
    """Start the application, load emails, parse them, analyze risk, and write a report."""
    configure_logging()
    args = build_argument_parser().parse_args(argv)

    try:
        source_dir = args.source.resolve()
        output_file = args.output.resolve()
        validate_source_directory(source_dir)
        validate_output_path(output_file)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    ingestor = EmailIngestor()
    ingested_emails, failed_count = ingestor.load_from_directory(source_dir)
    parser = EmailParser()
    parsed_emails = parser.parse_emails(ingested_emails)
    analyzer = HeuristicAnalyzer()
    scorer = RiskScorer()
    classifier = RiskClassifier()
    report_generator = ReportGenerator()
    analyzed_results: list[ScoredEmail] = []

    print(f"Loaded {len(parsed_emails)} emails ({failed_count} failed)")

    for email in parsed_emails:
        findings = analyzer.analyze(email)
        total_score = scorer.score(findings)
        classification = classifier.classify(total_score)
        scored_email = ScoredEmail(
            parsed_email=email,
            findings=findings,
            total_score=total_score,
            classification=classification,
        )
        analyzed_results.append(scored_email)
        print_email_details(scored_email)

    if args.summary:
        print_compact_summary(analyzed_results)

    try:
        report_path = report_generator.generate(analyzed_results, output_file)
    except OSError as exc:
        print(f"Error: unable to write report to {output_file}: {exc}", file=sys.stderr)
        return 1

    print()
    print(f"Total loaded: {len(parsed_emails)}")
    print(f"Total failed: {failed_count}")
    print(f"Report path: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
