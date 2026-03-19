# 📋 LogForensics — Log Analysis & Anomaly Detection

> Parses Windows, Linux, and Apache logs. Detects brute force, privilege escalation, and suspicious patterns with MITRE ATT&CK mapping.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ Features

- 🔍 **Auto-detect** log format (Windows / Linux / Apache)
- ⚠️ **Brute force detection** — flags IPs with 5+ failed logins
- 🗺️ **MITRE ATT&CK mapping** — every alert tagged with technique ID
- 📄 **JSON export** — ready for SIEM ingestion

## 🚀 Quick Start

```bash
git clone https://github.com/arash-123456/LogForensics.git
cd LogForensics
python logforensics.py -f /var/log/auth.log
python logforensics.py -f access.log -t apache -o report.json
```

## 🧠 Detects

- T1110 — Brute Force (SSH, RDP, Windows Logon)
- T1548 — Privilege Escalation (sudo, su)
- T1190 — Web Application Attacks (SQLi, LFI)
- T1595 — Reconnaissance (nmap, nikto, gobuster)
- T1021 — Lateral Movement (psexec, wmiexec)

## ⚖️ Legal Disclaimer

> Only analyze logs from systems you own or have explicit permission to monitor.
