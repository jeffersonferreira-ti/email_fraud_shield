"""Application entry point."""

from config import settings


def main() -> None:
    """Start the MVP application."""
    print(f"{settings.app_name} is ready.")
    print(f"Sample emails directory: {settings.samples_dir}")
    print(f"Output directory: {settings.output_dir}")


if __name__ == "__main__":
    main()
