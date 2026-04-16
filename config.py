"""Application configuration."""

from dataclasses import dataclass, field
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


@dataclass(slots=True)
class Settings:
    """Minimal settings container for the MVP."""

    app_name: str = "Email Fraud Shield"
    debug: bool = False
    samples_dir: Path = field(default_factory=lambda: BASE_DIR / "data" / "samples")
    output_dir: Path = field(default_factory=lambda: BASE_DIR / "data" / "output")
    output_file: Path = field(default_factory=lambda: BASE_DIR / "data" / "output" / "analysis_report.json")


settings = Settings()
