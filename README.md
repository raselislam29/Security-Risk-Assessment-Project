# Security Risk Assessment Project

A lightweight, extensible **Security Risk Assessment** tool written in Python.
It models assets and threats, computes risk scores, classifies them into risk
levels, and produces both human-readable console output and machine-readable
CSV reports.

---

## Features

| Feature | Details |
|---|---|
| **Asset modelling** | Define assets by name, type (Hardware / Software / Data / Network / Personnel / Facility) and business value (1–10) |
| **Threat modelling** | Define threats with likelihood (1–5) and impact (1–5) ratings |
| **Risk scoring** | `Score = (likelihood × impact × asset_value) / 10`; max score = 25 |
| **Risk classification** | LOW < 5 · MEDIUM 5–11 · HIGH 12–19 · CRITICAL ≥ 20 |
| **Console report** | Colour-coded tabular output sorted from highest to lowest risk |
| **CSV export** | Machine-readable export for spreadsheet analysis |

---

## Project Structure

```
Security-Risk-Assessment-Project/
├── src/
│   ├── __init__.py
│   ├── models.py      # Asset, Threat, RiskEntry data classes and enums
│   ├── engine.py      # Risk calculation and classification logic
│   ├── reporter.py    # Console and CSV output
│   └── cli.py         # Command-line interface
├── tests/
│   ├── __init__.py
│   └── test_assessment.py   # 26 unit tests
├── requirements.txt
└── README.md
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the built-in demo assessment

```bash
python -m src.cli
```

### 3. Export results to CSV

```bash
python -m src.cli --output report.csv
```

### 4. Disable ANSI colours (e.g. in CI logs)

```bash
python -m src.cli --no-colour
```

---

## Example Output

```
============================================================
  Security Risk Assessment: ACME Corp – Q1 2026 Assessment
  Assets: 6  |  Threats: 7
============================================================

------------------------------------------------------------------------------------------
Asset                     Type         Threat                           L   I  Score Level
------------------------------------------------------------------------------------------
Customer Database         Data         SQL Injection                    4   5   20.0 Critical
Customer Database         Data         Phishing Attack                  5   4   20.0 Critical
HR Records                Data         SQL Injection                    4   5   18.0 High
...
------------------------------------------------------------------------------------------

Summary:
  Low       : 5
  Medium    : 17
  High      : 18
  Critical  : 2
```

---

## Using the API Programmatically

```python
from src.models import Asset, AssetType, Threat, LikelihoodLevel, ImpactLevel, AssessmentConfig
from src.engine import assess
from src.reporter import print_report, export_csv

# 1. Create a configuration
config = AssessmentConfig(name="My Assessment")

# 2. Add assets
config.add_asset(Asset("Customer Database", AssetType.DATA, value=10))
config.add_asset(Asset("Web Application", AssetType.SOFTWARE, value=8))

# 3. Add threats
config.add_threat(Threat(
    "SQL Injection",
    "Attacker injects malicious SQL to access the database.",
    likelihood=LikelihoodLevel.HIGH,
    impact=ImpactLevel.CRITICAL,
))

# 4. Run the assessment
entries = assess(config)

# 5. Display results
print_report(entries)

# 6. Export to CSV
export_csv(entries, "my_report.csv")
```

---

## Risk Score Formula

```
Risk Score = (Likelihood × Impact × Asset Value) / 10
```

| Parameter | Scale | Description |
|---|---|---|
| Likelihood | 1 (Very Low) – 5 (Very High) | Probability the threat will be exploited |
| Impact | 1 (Negligible) – 5 (Critical) | Business damage if exploited |
| Asset Value | 1 (Minimal) – 10 (Mission Critical) | Relative importance of the asset |

### Risk Level Bands

| Score | Level |
|---|---|
| < 5 | 🟢 Low |
| 5 – 11.9 | 🟡 Medium |
| 12 – 19.9 | 🔴 High |
| ≥ 20 | 🚨 Critical |

---

## Running Tests

```bash
python -m pytest tests/ -v
```

All 26 unit tests cover:
- Asset and Threat validation
- Risk score calculation (including boundary values)
- Risk level classification
- Assessment engine (sorting, empty inputs, combinations)
- CSV and console reporting

---

## Licence

MIT
