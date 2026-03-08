# Security Risk Assessment Project

This repository combines two complementary outputs:

- A portfolio-ready, organization-wide cybersecurity risk assessment showcase.
- A lightweight Python tool that models assets/threats, calculates risk scores, and exports reports.

## Portfolio Showcase

The showcase demonstrates enterprise risk assessment across infrastructure, applications, and data assets, including mitigation planning and control mapping to NIST CSF and SOC 2.

### Showcase Deliverables

- `artifacts/risk_register.csv`: Detailed risk inventory with likelihood, impact, score, owners, and mitigation plans.
- `artifacts/control_mapping.md`: Gap-to-control mapping for NIST CSF and SOC 2 criteria.
- `artifacts/executive_summary.md`: Leadership summary of findings, impact, and 90-day plan.
- `artifacts/dashboard/dashboard.md`: Interview-friendly visual dashboard.
- `artifacts/dashboard/*.csv`: Dashboard datasets for charts and KPI summaries.

### Showcase Method Summary

1. Define critical assets and business context.
2. Identify threats, vulnerabilities, and existing controls.
3. Score risk with a 1-5 likelihood and 1-5 impact model.
4. Prioritize remediation by risk and business impact.
5. Map gaps to NIST CSF and SOC 2.

## Python Risk Assessment Tool

The Python tool computes risk scores and classifications and produces console and CSV reports.

### Features

| Feature | Details |
|---|---|
| Asset modelling | Define assets by name, type (Hardware / Software / Data / Network / Personnel / Facility), and business value (1-10) |
| Threat modelling | Define threats with likelihood (1-5) and impact (1-5) ratings |
| Risk scoring | `Score = (likelihood x impact x asset_value) / 10`; max score = 25 |
| Risk classification | LOW < 5, MEDIUM 5-11, HIGH 12-19, CRITICAL >= 20 |
| Console report | Colorized tabular output sorted high-to-low risk |
| CSV export | Machine-readable export for spreadsheet analysis |

### Project Structure

```text
Security-Risk-Assessment-Project/
|- artifacts/
|  |- dashboard/
|  |- control_mapping.md
|  |- executive_summary.md
|  |- risk_register.csv
|- src/
|  |- __init__.py
|  |- models.py
|  |- engine.py
|  |- reporter.py
|  |- cli.py
|- tests/
|  |- __init__.py
|  |- test_assessment.py
|- requirements.txt
|- README.md
```

### Quick Start

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the built-in demo assessment:

```bash
python -m src.cli
```

3. Export results to CSV:

```bash
python -m src.cli --output report.csv
```

4. Disable ANSI colors (for CI/log captures):

```bash
python -m src.cli --no-colour
```

### Risk Score Formula

```text
Risk Score = (Likelihood x Impact x Asset Value) / 10
```

### Risk Level Bands

| Score | Level |
|---|---|
| < 5 | Low |
| 5 - 11.9 | Medium |
| 12 - 19.9 | High |
| >= 20 | Critical |

### Running Tests

```bash
python -m pytest tests/ -v
```

## Resume / Portfolio Description

- Conducted an organization-wide cybersecurity risk assessment across infrastructure, applications, and data assets.
- Built a risk register with likelihood/impact scoring, prioritized remediation actions, and mitigation ownership.
- Mapped control gaps to NIST CSF and SOC 2 requirements to support compliance readiness and risk reduction.

## License

MIT
