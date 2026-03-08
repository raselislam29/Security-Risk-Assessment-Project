"""
Data models for the Security Risk Assessment system.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class AssetType(str, Enum):
    """Categories of assets that can be assessed."""
    HARDWARE = "Hardware"
    SOFTWARE = "Software"
    DATA = "Data"
    NETWORK = "Network"
    PERSONNEL = "Personnel"
    FACILITY = "Facility"


class LikelihoodLevel(int, Enum):
    """Likelihood that a threat will exploit a vulnerability (1–5)."""
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    VERY_HIGH = 5


class ImpactLevel(int, Enum):
    """Business impact if a threat is successfully exploited (1–5)."""
    NEGLIGIBLE = 1
    MINOR = 2
    MODERATE = 3
    SIGNIFICANT = 4
    CRITICAL = 5


class RiskLevel(str, Enum):
    """Overall risk classification derived from the risk score."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class Asset:
    """Represents a business or technical asset to be protected."""
    name: str
    asset_type: AssetType
    value: int  # 1–10: relative business value of the asset

    def __post_init__(self):
        if not 1 <= self.value <= 10:
            raise ValueError(f"Asset value must be between 1 and 10, got {self.value}")
        if not self.name.strip():
            raise ValueError("Asset name must not be empty")


@dataclass
class Threat:
    """Represents a threat that may affect one or more assets."""
    name: str
    description: str
    likelihood: LikelihoodLevel
    impact: ImpactLevel

    def __post_init__(self):
        if not self.name.strip():
            raise ValueError("Threat name must not be empty")


@dataclass
class RiskEntry:
    """The result of assessing a single threat against a single asset."""
    asset: Asset
    threat: Threat
    risk_score: float
    risk_level: RiskLevel
    mitigation: str = ""

    def to_dict(self) -> dict:
        return {
            "asset": self.asset.name,
            "asset_type": self.asset.asset_type.value,
            "asset_value": self.asset.value,
            "threat": self.threat.name,
            "threat_description": self.threat.description,
            "likelihood": self.threat.likelihood.value,
            "impact": self.threat.impact.value,
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level.value,
            "mitigation": self.mitigation,
        }


@dataclass
class AssessmentConfig:
    """Holds all assets and threats for an assessment session."""
    name: str
    assets: List[Asset] = field(default_factory=list)
    threats: List[Threat] = field(default_factory=list)

    def add_asset(self, asset: Asset) -> None:
        self.assets.append(asset)

    def add_threat(self, threat: Threat) -> None:
        self.threats.append(threat)
