# 🛡 Adaptive Cyber Defense & Attack Surface Analyzer

## 📌 Overview
This project simulates an enterprise-level cybersecurity risk assessment platform.  
It performs intelligent service enumeration, vulnerability intelligence correlation, attack surface mapping, and dynamic CVSS-based risk modeling.

## 🔍 Features

- Multi-target enterprise scanning
- TCP & UDP service enumeration
- OS fingerprinting
- Threat Intelligence correlation (CVE matching)
- CVSS-based dynamic risk scoring
- Exploit awareness detection
- Attack surface exposure analysis
- Defensive mitigation recommendations
- JSON structured reporting
- HTML security dashboard
- SOC-style logging simulation

## 🏗 Architecture

Core Modules:
- scanner engine (TCP/UDP)
- OS detection module
- banner grabbing module
- risk modeling engine
- threat intelligence engine
- attack surface mapper
- reporting engine
- logging module

## 📊 Risk Modeling Strategy

Risk is calculated based on:
- Service exposure base score
- CVSS score
- Exploit availability multiplier

Risk Levels:
- LOW
- MEDIUM
- HIGH
- CRITICAL

## 📁 Output

- `defensive_scan_report.json`
- `defensive_scan_report.html`
- `logs/scan.log`

## 🚀 How To Run

```bash
python main.py

🎯 Academic Domain

Cybersecurity
Network Defense
Threat Modeling
Security Risk Assessment
SOC Simulation

#This system simulates a Security Operations Center workflow by combining attack surface discovery, threat intelligence correlation, exploit-aware CVSS modeling, and enterprise-level reporting.
