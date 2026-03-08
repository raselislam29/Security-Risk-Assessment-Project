"""
Command-Line Interface for the Security Risk Assessment tool.

Usage:
    python -m src.cli                        # run built-in demo
    python -m src.cli --output report.csv    # also export to CSV
    python -m src.cli --no-colour            # disable ANSI colours
"""

import argparse
import sys

from .engine import assess
from .models import (
    Asset,
    AssetType,
    AssessmentConfig,
    ImpactLevel,
    LikelihoodLevel,
    Threat,
)
from .reporter import export_csv, print_report


def _build_demo_config() -> AssessmentConfig:
    """Return a realistic sample configuration for demonstration purposes."""
    config = AssessmentConfig(name="ACME Corp – Q1 2026 Assessment")

    # Assets
    config.add_asset(Asset("Customer Database", AssetType.DATA, value=10))
    config.add_asset(Asset("Web Application", AssetType.SOFTWARE, value=8))
    config.add_asset(Asset("Corporate Laptops", AssetType.HARDWARE, value=6))
    config.add_asset(Asset("Internal Network", AssetType.NETWORK, value=7))
    config.add_asset(Asset("HR Records", AssetType.DATA, value=9))
    config.add_asset(Asset("Data Centre", AssetType.FACILITY, value=8))

    # Threats
    config.add_threat(Threat(
        "SQL Injection",
        "Attacker injects malicious SQL into an input field to access or corrupt the database.",
        likelihood=LikelihoodLevel.HIGH,
        impact=ImpactLevel.CRITICAL,
    ))
    config.add_threat(Threat(
        "Phishing Attack",
        "Employees tricked into revealing credentials via fraudulent emails.",
        likelihood=LikelihoodLevel.VERY_HIGH,
        impact=ImpactLevel.SIGNIFICANT,
    ))
    config.add_threat(Threat(
        "Ransomware",
        "Malicious software encrypts files and demands payment.",
        likelihood=LikelihoodLevel.MEDIUM,
        impact=ImpactLevel.CRITICAL,
    ))
    config.add_threat(Threat(
        "Insider Threat",
        "Malicious or negligent employee leaks or destroys data.",
        likelihood=LikelihoodLevel.LOW,
        impact=ImpactLevel.SIGNIFICANT,
    ))
    config.add_threat(Threat(
        "DDoS Attack",
        "Distributed denial-of-service floods services making them unavailable.",
        likelihood=LikelihoodLevel.MEDIUM,
        impact=ImpactLevel.MODERATE,
    ))
    config.add_threat(Threat(
        "Physical Intrusion",
        "Unauthorised physical access to facilities or hardware.",
        likelihood=LikelihoodLevel.LOW,
        impact=ImpactLevel.MODERATE,
    ))
    config.add_threat(Threat(
        "Unpatched Software",
        "Known vulnerabilities in software are left unpatched and exploited.",
        likelihood=LikelihoodLevel.HIGH,
        impact=ImpactLevel.SIGNIFICANT,
    ))

    return config


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Security Risk Assessment Tool – evaluate and report risks."
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Export results to a CSV file (e.g. report.csv)",
    )
    parser.add_argument(
        "--no-colour",
        action="store_true",
        help="Disable ANSI colour codes in terminal output",
    )
    args = parser.parse_args(argv)

    config = _build_demo_config()
    print(f"\n{'='*60}")
    print(f"  Security Risk Assessment: {config.name}")
    print(f"  Assets: {len(config.assets)}  |  Threats: {len(config.threats)}")
    print(f"{'='*60}\n")

    entries = assess(config)
    print_report(entries, use_colour=not args.no_colour)

    if args.output:
        export_csv(entries, args.output)
        print(f"Report exported to: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
