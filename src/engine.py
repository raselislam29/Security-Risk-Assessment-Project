"""
Risk Assessment Engine.

Calculates risk scores for every (asset, threat) pair and classifies them
into LOW / MEDIUM / HIGH / CRITICAL bands.

Risk Score = (likelihood × impact × asset_value) / 10
"""

from typing import List

from .models import Asset, AssessmentConfig, RiskEntry, RiskLevel, Threat


def _classify_risk(score: float) -> RiskLevel:
    """Map a numeric risk score to a qualitative RiskLevel."""
    if score < 5:
        return RiskLevel.LOW
    if score < 12:
        return RiskLevel.MEDIUM
    if score < 20:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def calculate_risk_score(asset: Asset, threat: Threat) -> float:
    """
    Compute the risk score for a single (asset, threat) pair.

    Score = (likelihood × impact × asset_value) / 10
    Maximum possible score: 5 × 5 × 10 / 10 = 25
    """
    return (threat.likelihood.value * threat.impact.value * asset.value) / 10.0


def assess(config: AssessmentConfig) -> List[RiskEntry]:
    """
    Run the full risk assessment for a given configuration.

    Returns a list of RiskEntry objects, one per (asset, threat) combination,
    sorted from highest risk score to lowest.
    """
    entries: List[RiskEntry] = []

    for asset in config.assets:
        for threat in config.threats:
            score = calculate_risk_score(asset, threat)
            level = _classify_risk(score)
            entries.append(RiskEntry(asset=asset, threat=threat, risk_score=score, risk_level=level))

    entries.sort(key=lambda e: e.risk_score, reverse=True)
    return entries
