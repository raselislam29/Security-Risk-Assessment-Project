"""
Unit tests for the Security Risk Assessment project.
"""

import csv
import io
import unittest

from src.engine import assess, calculate_risk_score, _classify_risk
from src.models import (
    Asset,
    AssetType,
    AssessmentConfig,
    ImpactLevel,
    LikelihoodLevel,
    RiskEntry,
    RiskLevel,
    Threat,
)
from src.reporter import generate_csv_string, print_report


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_asset(name="Web Server", asset_type=AssetType.SOFTWARE, value=5):
    return Asset(name=name, asset_type=asset_type, value=value)


def _make_threat(
    name="SQL Injection",
    likelihood=LikelihoodLevel.HIGH,
    impact=ImpactLevel.CRITICAL,
):
    return Threat(
        name=name,
        description="Test threat",
        likelihood=likelihood,
        impact=impact,
    )


# ---------------------------------------------------------------------------
# Asset model
# ---------------------------------------------------------------------------

class TestAsset(unittest.TestCase):

    def test_valid_asset_created(self):
        asset = _make_asset()
        self.assertEqual(asset.name, "Web Server")
        self.assertEqual(asset.asset_type, AssetType.SOFTWARE)
        self.assertEqual(asset.value, 5)

    def test_asset_value_below_minimum_raises(self):
        with self.assertRaises(ValueError):
            Asset("Bad Asset", AssetType.DATA, value=0)

    def test_asset_value_above_maximum_raises(self):
        with self.assertRaises(ValueError):
            Asset("Bad Asset", AssetType.DATA, value=11)

    def test_empty_name_raises(self):
        with self.assertRaises(ValueError):
            Asset("  ", AssetType.DATA, value=5)

    def test_boundary_values(self):
        Asset("Min", AssetType.HARDWARE, value=1)
        Asset("Max", AssetType.HARDWARE, value=10)


# ---------------------------------------------------------------------------
# Threat model
# ---------------------------------------------------------------------------

class TestThreat(unittest.TestCase):

    def test_valid_threat_created(self):
        threat = _make_threat()
        self.assertEqual(threat.name, "SQL Injection")
        self.assertEqual(threat.likelihood, LikelihoodLevel.HIGH)
        self.assertEqual(threat.impact, ImpactLevel.CRITICAL)

    def test_empty_name_raises(self):
        with self.assertRaises(ValueError):
            Threat("  ", "desc", LikelihoodLevel.LOW, ImpactLevel.MINOR)


# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------

class TestCalculateRiskScore(unittest.TestCase):

    def test_known_score(self):
        # likelihood=4, impact=5, value=10 → (4×5×10)/10 = 20.0
        asset = _make_asset(value=10)
        threat = _make_threat(likelihood=LikelihoodLevel.HIGH, impact=ImpactLevel.CRITICAL)
        self.assertAlmostEqual(calculate_risk_score(asset, threat), 20.0)

    def test_minimum_score(self):
        # likelihood=1, impact=1, value=1 → (1×1×1)/10 = 0.1
        asset = _make_asset(value=1)
        threat = _make_threat(likelihood=LikelihoodLevel.VERY_LOW, impact=ImpactLevel.NEGLIGIBLE)
        self.assertAlmostEqual(calculate_risk_score(asset, threat), 0.1)

    def test_maximum_score(self):
        # likelihood=5, impact=5, value=10 → (5×5×10)/10 = 25.0
        asset = _make_asset(value=10)
        threat = _make_threat(likelihood=LikelihoodLevel.VERY_HIGH, impact=ImpactLevel.CRITICAL)
        self.assertAlmostEqual(calculate_risk_score(asset, threat), 25.0)


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------

class TestClassifyRisk(unittest.TestCase):

    def test_low(self):
        self.assertEqual(_classify_risk(0.1), RiskLevel.LOW)
        self.assertEqual(_classify_risk(4.9), RiskLevel.LOW)

    def test_medium(self):
        self.assertEqual(_classify_risk(5.0), RiskLevel.MEDIUM)
        self.assertEqual(_classify_risk(11.9), RiskLevel.MEDIUM)

    def test_high(self):
        self.assertEqual(_classify_risk(12.0), RiskLevel.HIGH)
        self.assertEqual(_classify_risk(19.9), RiskLevel.HIGH)

    def test_critical(self):
        self.assertEqual(_classify_risk(20.0), RiskLevel.CRITICAL)
        self.assertEqual(_classify_risk(25.0), RiskLevel.CRITICAL)


# ---------------------------------------------------------------------------
# Assessment engine
# ---------------------------------------------------------------------------

class TestAssessEngine(unittest.TestCase):

    def _make_config(self):
        config = AssessmentConfig(name="Test Assessment")
        config.add_asset(_make_asset("Asset A", AssetType.DATA, value=8))
        config.add_asset(_make_asset("Asset B", AssetType.NETWORK, value=3))
        config.add_threat(_make_threat("Threat X", LikelihoodLevel.HIGH, ImpactLevel.CRITICAL))
        config.add_threat(_make_threat("Threat Y", LikelihoodLevel.LOW, ImpactLevel.MINOR))
        return config

    def test_returns_correct_number_of_entries(self):
        config = self._make_config()
        entries = assess(config)
        self.assertEqual(len(entries), 4)  # 2 assets × 2 threats

    def test_entries_sorted_descending_by_score(self):
        config = self._make_config()
        entries = assess(config)
        scores = [e.risk_score for e in entries]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_empty_config_returns_empty_list(self):
        config = AssessmentConfig(name="Empty")
        self.assertEqual(assess(config), [])

    def test_no_threats_returns_empty_list(self):
        config = AssessmentConfig(name="No Threats")
        config.add_asset(_make_asset())
        self.assertEqual(assess(config), [])

    def test_no_assets_returns_empty_list(self):
        config = AssessmentConfig(name="No Assets")
        config.add_threat(_make_threat())
        self.assertEqual(assess(config), [])

    def test_risk_level_populated(self):
        config = self._make_config()
        entries = assess(config)
        for entry in entries:
            self.assertIsInstance(entry.risk_level, RiskLevel)


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

class TestReporter(unittest.TestCase):

    def _make_entry(self, score=15.0, level=RiskLevel.HIGH):
        return RiskEntry(
            asset=_make_asset(),
            threat=_make_threat(),
            risk_score=score,
            risk_level=level,
            mitigation="Apply WAF rules",
        )

    def test_generate_csv_string_has_header(self):
        entry = self._make_entry()
        csv_text = generate_csv_string([entry])
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertIn("risk_score", rows[0])
        self.assertIn("risk_level", rows[0])

    def test_generate_csv_string_empty(self):
        self.assertEqual(generate_csv_string([]), "")

    def test_csv_values_correct(self):
        entry = self._make_entry(score=15.0, level=RiskLevel.HIGH)
        csv_text = generate_csv_string([entry])
        reader = csv.DictReader(io.StringIO(csv_text))
        row = next(reader)
        self.assertEqual(row["asset"], "Web Server")
        self.assertEqual(row["risk_level"], "High")
        self.assertEqual(float(row["risk_score"]), 15.0)
        self.assertEqual(row["mitigation"], "Apply WAF rules")

    def test_print_report_runs_without_error(self):
        """Smoke test: print_report should not raise an exception."""
        entry = self._make_entry()
        # Redirect stdout to suppress output during test
        import sys
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            print_report([entry], use_colour=False)
        finally:
            sys.stdout = old_stdout


# ---------------------------------------------------------------------------
# AssessmentConfig
# ---------------------------------------------------------------------------

class TestAssessmentConfig(unittest.TestCase):

    def test_add_asset_and_threat(self):
        config = AssessmentConfig(name="Config Test")
        config.add_asset(_make_asset())
        config.add_threat(_make_threat())
        self.assertEqual(len(config.assets), 1)
        self.assertEqual(len(config.threats), 1)

    def test_to_dict_completeness(self):
        entry = RiskEntry(
            asset=_make_asset(),
            threat=_make_threat(),
            risk_score=10.5,
            risk_level=RiskLevel.MEDIUM,
        )
        d = entry.to_dict()
        expected_keys = {
            "asset", "asset_type", "asset_value", "threat",
            "threat_description", "likelihood", "impact",
            "risk_score", "risk_level", "mitigation",
        }
        self.assertEqual(set(d.keys()), expected_keys)


if __name__ == "__main__":
    unittest.main()
