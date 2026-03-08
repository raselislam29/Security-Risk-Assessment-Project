# Control Gap Mapping: NIST CSF and SOC 2

This matrix maps identified security gaps to both NIST CSF and SOC 2 Trust Services Criteria to support remediation prioritization and compliance readiness.

## Mapping Table

| Risk ID | Gap Summary | NIST CSF Function / Category | SOC 2 Trust Criteria | Recommended Control Improvement |
|---|---|---|---|---|
| R-001 | Excessive privileged standing access | PR.AA (Identity Management, Authentication, and Access Control) | CC6.1, CC6.2, CC6.3 | Implement PAM with just-in-time privileged access and automated periodic recertification |
| R-002 | Unmanaged endpoints and delayed patching | PR.IP (Platform Security), DE.CM (Security Continuous Monitoring) | CC7.1, CC7.2 | Expand asset discovery and enforce risk-based patch SLAs with compliance reporting |
| R-003 | Flat network architecture enables lateral movement | PR.PS (Platform Security), PR.IR (Technology Resilience) | CC6.6, CC7.1 | Segment critical systems and restrict east-west traffic using least-privilege network policies |
| R-004 | Inconsistent security testing in SDLC | PR.PS (Secure Development and Change Management) | CC8.1, CC8.2 | Mandate SAST/DAST and security sign-off within CI/CD release controls |
| R-005 | Secrets embedded in source code | PR.AA, PR.PS | CC6.1, CC6.7 | Centralize secrets in vault and enforce commit-time secret scanning/blocking |
| R-006 | Insufficient centralized audit logging | DE.CM (Monitoring), RS.AN (Incident Analysis) | CC7.2, CC7.3 | Centralize logs in SIEM with alert use cases and evidentiary retention |
| R-007 | Inconsistent data classification | ID.AM (Asset Management), PR.DS (Data Security) | C1.1, CC3.2, CC6.1 | Formalize data classification standard and handling requirements by data class |
| R-008 | Legacy data stores without encryption at rest | PR.DS (Data Security) | C1.2, CC6.1, CC6.7 | Enforce encryption at rest and key lifecycle management for all sensitive stores |
| R-009 | Untested backup restores | PR.IR (Technology Resilience), RC.RP (Recovery Planning) | A1.2, CC7.4 | Execute routine recovery drills and track RTO/RPO performance against targets |
| R-010 | Incomplete third-party reassessment | ID.RM (Risk Management Strategy), GV.SC (Supply Chain Risk Management) | CC9.2, CC9.3 | Establish annual vendor due diligence and remediation follow-up workflow |

## Notes

- NIST CSF references use function/category-level mappings for clarity in executive reporting.
- SOC 2 references align to common criteria used in security and availability-focused audits.
- This table should be updated as controls mature and residual risk scores change.
