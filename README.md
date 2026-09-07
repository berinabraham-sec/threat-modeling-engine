# Threat Modeling Engine

A comprehensive threat modeling tool that analyzes endpoint configurations, generates attack trees, maps to MITRE ATT&CK, calculates risk scores, and recommends security controls with cost-benefit analysis.

---

## Overview

The Threat Modeling Engine is a professional security tool designed to help security engineers, architects, and GRC analysts assess endpoint security posture, identify threats, prioritize risks, and recommend appropriate controls.

### Key Features

- Attack Tree Generation: Creates visual attack trees based on endpoint configuration (OS, software, controls)
- MITRE ATT&CK Mapping: Maps threats to MITRE ATT&CK v12 techniques with confidence scoring
- Quantitative Risk Scoring: Calculates risk scores (0-10) using a weighted methodology
- Business Impact Analysis: Translates technical risks into business impact with financial estimates
- Control Recommendations: Recommends security controls with ROI and priority scoring
- Executive Reporting: Generates professional HTML and console reports
- Cross-Platform Support: Supports Windows, Linux, and macOS endpoints

---

## Methodology

### Risk Scoring

The engine calculates risk scores using a weighted methodology:

| Component | Weight | Description |
|-----------|--------|-------------|
| CVSS Score | 35% | Common Vulnerability Scoring System base score |
| EPSS Score | 25% | Exploit Prediction Scoring System probability |
| Asset Criticality | 20% | Business criticality rating (1-5) |
| Exploit Maturity | 20% | Availability and maturity of public exploits |

### Risk Levels

| Level | Score Range | Response |
|-------|-------------|----------|
| CRITICAL | 8.0 - 10.0 | Immediate action required |
| HIGH | 6.0 - 7.9 | Prioritize within 7 days |
| MEDIUM | 4.0 - 5.9 | Plan within 30 days |
| LOW | 0.0 - 3.9 | Monitor and evaluate |

### MITRE ATT&CK Integration

The engine maps threats to 20+ MITRE ATT&CK v12 techniques:

| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1078 | Valid Accounts | Initial Access |
| T1003 | Credential Dumping | Credential Access |
| T1021 | Remote Services | Lateral Movement |
| T1059 | Command and Scripting Interpreter | Execution |
| T1566 | Phishing | Initial Access |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1486 | Data Encrypted for Impact | Impact |
| T1562 | Impair Defenses | Defense Evasion |
| T1046 | Network Service Discovery | Discovery |
| T1071 | Application Layer Protocol | Command and Control |
| T1133 | External Remote Services | Persistence |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1087 | Account Discovery | Discovery |

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- SQLite3 (built into Python)

### Step 1: Clone the Repository

git clone https://github.com/berinabraham-sec/threat-modeling-engine.git
cd threat-modeling-engine

### Step 2: Install Dependencies

pip install click

### Step 3: Run the Engine

python threat_modeling_engine.py

---

## Usage

### Quick Start: Run the Demo

The script automatically runs a demo with 5 sample endpoints:

python threat_modeling_engine.py

### Sample Output

================================================================================
THREAT MODELING ENGINE - DEMO
================================================================================

Generating sample endpoints and threat models...
  Created: Production Web Server
  Created: Database Server
  Created: Developer Workstation
  Created: API Gateway
  Created: HR Workstation

Created 5 endpoints

Running threat assessments...

Analyzing: Production Web Server
----------------------------------------
  Risk Score: 8.40
  Risk Level: CRITICAL

Analyzing: Database Server
----------------------------------------
  Risk Score: 6.19
  Risk Level: HIGH

================================================================================
GENERATING REPORTS
================================================================================

================================================================================
THREAT MODELING REPORT
================================================================================
Generated: 2026-09-06 22:27:35
--------------------------------------------------------------------------------

ENDPOINT INFORMATION:
  Name: Production Web Server
  OS Type: Windows
  Asset Criticality: 5/5

THREAT MODEL:
  Risk Score: 8.40/10
  Risk Level: CRITICAL
  Attack Vector: Social Engineering

BUSINESS IMPACT:
  Potential compromise of Production Web Server. Estimated financial impact: $273541.

MITRE ATT&CK TECHNIQUES:
  - T1078: Valid Accounts
  - T1003: Credential Dumping
  - T1021: Remote Services

CONTROL RECOMMENDATIONS:
  1. Multi-Factor Authentication (MFA)
     Category: Preventive
     Effectiveness: 8.5/10
     Cost: 3.0/10
     Implementation: 2-4 weeks

  2. Endpoint Detection and Response (EDR)
     Category: Detective
     Effectiveness: 7.5/10
     Cost: 5.0/10
     Implementation: 4-6 weeks

================================================================================
HTML report saved: reports/threat_report_Production Web Server_20260906_222735.html
================================================================================
DEMO COMPLETE
================================================================================

### Add a Custom Endpoint

To add your own endpoints, modify the SAMPLE_ENDPOINTS list in the script:

SAMPLE_ENDPOINTS = [
    {
        'name': 'My Custom Server',
        'os_type': 'Windows',
        'os_version': 'Server 2022',
        'software': ['IIS', 'Chrome', 'OpenSSL'],
        'controls': ['MFA', 'EDR', 'Vulnerability Scanning'],
        'asset_criticality': 5
    }
]

---

## Reports

### Console Report

The console report displays endpoint information, risk score and level, MITRE ATT&CK techniques mapped, and recommended controls with category, effectiveness, cost, and implementation time.

### HTML Report

The HTML report provides a professional dashboard with risk score visualization, risk level badge, control recommendations with ROI, and a professional dark theme suitable for stakeholders.

---

## Architecture

The engine follows a four-layer architecture:

Layer 1 - Configuration Ingestion: OS Info, Software, Controls
Layer 2 - Threat Modeling Engine: Attack Tree Generation, MITRE Mapping, Risk Scoring
Layer 3 - Control Recommendation Engine: Control Mapping, Effectiveness Scoring, Prioritization
Layer 4 - Report Generator: Console Reports, HTML Dashboards, JSON Exports

---

## Control Library

The engine includes a comprehensive control library:

| Control | Category | Effectiveness | Cost | Implementation |
|---------|----------|---------------|------|----------------|
| Multi-Factor Authentication (MFA) | Preventive | 8.5/10 | 3.0/10 | 2-4 weeks |
| Endpoint Detection and Response (EDR) | Detective | 7.5/10 | 5.0/10 | 4-6 weeks |
| Security Awareness Training | Preventive | 6.0/10 | 2.0/10 | Ongoing |
| Backup and Recovery | Corrective | 9.0/10 | 4.0/10 | 2-4 weeks |
| Network Segmentation | Preventive | 7.0/10 | 5.0/10 | 4-8 weeks |
| Data Loss Prevention (DLP) | Preventive | 7.0/10 | 6.0/10 | 4-8 weeks |
| Incident Response Plan | Corrective | 8.0/10 | 4.0/10 | 8-12 weeks |
| Vulnerability Scanning | Detective | 6.5/10 | 3.0/10 | Ongoing |
| SIEM Implementation | Detective | 7.0/10 | 7.0/10 | 8-16 weeks |
| Zero Trust Architecture | Preventive | 8.5/10 | 8.0/10 | 12-24 weeks |
| Application Whitelisting | Preventive | 7.5/10 | 4.0/10 | 4-8 weeks |
| Privileged Access Management (PAM) | Preventive | 8.0/10 | 6.0/10 | 8-12 weeks |

---

## Project Structure

threat-modeling-engine/
- threat_modeling_engine.py          # Main application
- README.md                          # Documentation
- threat_modeling.db                 # SQLite database (generated)
- reports/                           # Generated reports
- logs/                              # Application logs (optional)

---

## Database Schema

### Endpoints Table

- endpoint_id: Unique identifier
- name: Endpoint name
- os_type: Windows, Linux, macOS
- os_version: Operating system version
- software: JSON array of software
- controls: JSON array of controls
- asset_criticality: 1-5 criticality rating

### Threat Models Table

- model_id: Unique identifier
- endpoint_id: Reference to endpoint
- attack_tree: JSON attack tree
- mitre_techniques: JSON MITRE techniques
- risk_score: 0-10 risk score
- risk_level: CRITICAL/HIGH/MEDIUM/LOW

---

## Troubleshooting

### Common Issues

Click Not Found:
pip install click

Database Errors:
rm threat_modeling.db
python threat_modeling_engine.py

Permission Denied on Reports:
mkdir reports
python threat_modeling_engine.py

No Output from Script:
Make sure you're using Python 3.8+:
python --version

---

## Contributing

Contributions are welcome. Please submit a pull request or open an issue for discussion.

---

## Author

berinabraham-sec

GitHub: https://github.com/berinabraham-sec

---

## License

MIT License

---

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- NIST SP 800-53 Rev. 5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- CVSS v3.1 Specification: https://www.first.org/cvss/v3.1/specification-document
- FIRST EPSS: https://www.first.org/epss/

---

## Quick Reference

### Risk Levels

| Level | Score | Response |
|-------|-------|----------|
| CRITICAL | 8.0+ | Immediate |
| HIGH | 6.0-7.9 | 7 Days |
| MEDIUM | 4.0-5.9 | 30 Days |
| LOW | 0.0-3.9 | Monitor |

### MITRE Tactic Coverage

| Tactic | Techniques |
|--------|------------|
| Initial Access | T1078, T1566, T1190 |
| Execution | T1059, T1053 |
| Persistence | T1133, T1136, T1098 |
| Privilege Escalation | T1548, T1068 |
| Defense Evasion | T1562 |
| Credential Access | T1003 |
| Discovery | T1087, T1046 |
| Lateral Movement | T1021, T1550 |
| Command and Control | T1071, T1105 |
| Impact | T1486 |

---

End of Documentation