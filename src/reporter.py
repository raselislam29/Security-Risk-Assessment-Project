"""
Report generation for Security Risk Assessment results.

Supports:
  - Console (tabular) output
  - CSV file export
"""

import csv
import io
from typing import List

from .models import RiskEntry, RiskLevel

# ANSI colour codes for terminal output
_COLOURS = {
    RiskLevel.LOW: "\033[32m",       # green
    RiskLevel.MEDIUM: "\033[33m",    # yellow
    RiskLevel.HIGH: "\033[91m",      # bright red
    RiskLevel.CRITICAL: "\033[1;31m",# bold red
}
_RESET = "\033[0m"

_HEADER = (
    f"{'Asset':<25} {'Type':<12} {'Threat':<30} "
    f"{'L':>3} {'I':>3} {'Score':>6} {'Level':<10} Mitigation"
)
_SEPARATOR = "-" * len(_HEADER)


def _colour(text: str, level: RiskLevel, use_colour: bool) -> str:
    if not use_colour:
        return text
    return f"{_COLOURS.get(level, '')}{text}{_RESET}"


def print_report(entries: List[RiskEntry], use_colour: bool = True) -> None:
    """Print a formatted risk assessment table to stdout."""
    print(_SEPARATOR)
    print(_HEADER)
    print(_SEPARATOR)
    for entry in entries:
        row = (
            f"{entry.asset.name:<25} "
            f"{entry.asset.asset_type.value:<12} "
            f"{entry.threat.name:<30} "
            f"{entry.threat.likelihood.value:>3} "
            f"{entry.threat.impact.value:>3} "
            f"{entry.risk_score:>6.1f} "
            f"{entry.risk_level.value:<10} "
            f"{entry.mitigation or '—'}"
        )
        print(_colour(row, entry.risk_level, use_colour))
    print(_SEPARATOR)
    _print_summary(entries, use_colour)


def _print_summary(entries: List[RiskEntry], use_colour: bool) -> None:
    totals = {level: 0 for level in RiskLevel}
    for e in entries:
        totals[e.risk_level] += 1

    print("\nSummary:")
    for level, count in totals.items():
        label = f"  {level.value:<10}: {count}"
        print(_colour(label, level, use_colour))
    print()


def export_csv(entries: List[RiskEntry], filepath: str) -> None:
    """Export all risk entries to a CSV file."""
    if not entries:
        return
    fieldnames = list(entries[0].to_dict().keys())
    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow(entry.to_dict())


def generate_csv_string(entries: List[RiskEntry]) -> str:
    """Return CSV content as a string (useful for testing)."""
    if not entries:
        return ""
    output = io.StringIO()
    fieldnames = list(entries[0].to_dict().keys())
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for entry in entries:
        writer.writerow(entry.to_dict())
    return output.getvalue()
