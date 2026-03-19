#!/usr/bin/env python3

"""
LogForensics - Log Parsing & Anomaly Detection Engine
Author: Arash | GitHub: github.com/arash-123456
Parses Windows Event Logs, Linux auth logs, and web server logs.
Detects brute force, privilege escalation, and suspicious patterns.
"""

import re
import json
import argparse
import sys
from datetime import datetime
from collections import defaultdict, Counter
from typing import Optional
from pathlib import Path

# ─────────────────────────────────────────────
# Detection Signatures
# ─────────────────────────────────────────────

WINDOWS_EVENT_IDS = {
    "4624": ("Successful Logon", "INFO"),
    "4625": ("Failed Logon", "MEDIUM"),
    "4634": ("Logoff", "INFO"),
    "4648": ("Logon with explicit credentials (PtH?)", "HIGH"),
    "4672": ("Special privileges assigned", "MEDIUM"),
    "4688": ("New process created", "INFO"),
    "4697": ("Service installed", "HIGH"),
    "4698": ("Scheduled task created", "HIGH"),
    "4720": ("User account created", "HIGH"),
    "4732": ("User added to privileged group", "HIGH"),
    "4756": ("Member added to universal group", "HIGH"),
    "1102": ("Audit log cleared", "CRITICAL"),
    "7045": ("New service installed", "HIGH"),
}

SUSPICIOUS_PATTERNS = {
    "brute_force": re.compile(r"(Failed password|authentication failure|Invalid user)", re.I),
    "privilege_esc": re.compile(r"(sudo|su |privilege|root|administrator)", re.I),
    "web_attack": re.compile(r"(\.\./|union select|<script|cmd\.exe|\/etc\/passwd|wget http)", re.I),
    "recon": re.compile(r"(nmap|masscan|nikto|gobuster|dirb|sqlmap)", re.I),
    "lateral_movement": re.compile(r"(psexec|wmiexec|smbexec|winrm|powershell.*-enc)", re.I),
}

# Threshold for brute force detection
BRUTE_FORCE_THRESHOLD = 5  # failed attempts within window


class LogParser:

    def __init__(self, log_type: str = "auto"):
        self.log_type = log_type
        self.events = []
        self.alerts = []
        self.stats = defaultdict(int)

    def detect_log_type(self, sample: str) -> str:
        """Auto-detect log format from sample lines."""
        if re.search(r"EventID|Event ID|Security|Application", sample):
            return "windows"
        elif re.search(r"sshd|auth|pam|sudo", sample, re.I):
            return "linux_auth"
        elif re.search(r'"\w+ /\S+ HTTP/', sample):
            return "apache"
        return "generic"

    def parse_linux_auth(self, line: str) -> Optional[dict]:
        """Parse Linux /var/log/auth.log format."""
        pattern = re.compile(
            r"(\w+\s+\d+\s[\d:]+)\s+(\S+)\s+(\w+)(?:\[(\d+)\])?:\s+(.*)"
        )
        match = pattern.match(line)
        if match:
            timestamp, host, service, pid, message = match.groups()
            return {
                "timestamp": timestamp,
                "host": host,
                "service": service,
                "pid": pid,
                "message": message,
                "raw": line
            }
        return None

    def parse_apache(self, line: str) -> Optional[dict]:
        """Parse Apache/Nginx combined log format."""
        pattern = re.compile(
            r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
        )
        match = pattern.match(line)
        if match:
            ip, timestamp, method, path, status, size = match.groups()
            return {
                "ip": ip,
                "timestamp": timestamp,
                "method": method,
                "path": path,
                "status": int(status),
                "size": int(size),
                "raw": line
            }
        return None

    def parse_windows_event(self, line: str) -> Optional[dict]:
        """Parse Windows Security Event Log format."""
        event_id_match = re.search(r"EventID[=:\s]+(\d+)", line)
        if event_id_match:
            event_id = event_id_match.group(1)
            description, severity = WINDOWS_EVENT_IDS.get(event_id, ("Unknown Event", "INFO"))
            return {
                "event_id": event_id,
                "description": description,
                "severity": severity,
                "raw": line
            }
        return None

    def detect_anomalies(self, parsed_events: list) -> list:
        """Run anomaly detection across parsed events."""
        alerts = []
        failed_logins = defaultdict(list)
        ips = Counter()

        for event in parsed_events:
            raw = event.get("raw", "")

            # Check suspicious patterns
            for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
                if pattern.search(raw):
                    if pattern_name == "brute_force":
                        ip = event.get("ip", "unknown")
                        failed_logins[ip].append(event)
                        ips[ip] += 1
                    else:
                        alerts.append({
                            "type": pattern_name,
                            "severity": "HIGH" if pattern_name in ("lateral_movement", "privilege_esc") else "MEDIUM",
                            "detail": raw[:200],
                            "mitre": self._get_mitre(pattern_name)
                        })

            # Check Windows Event IDs
            if "event_id" in event and event["severity"] in ("HIGH", "CRITICAL"):
                alerts.append({
                    "type": "windows_event",
                    "severity": event["severity"],
                    "event_id": event["event_id"],
                    "detail": event["description"],
                    "mitre": "T1078"
                })

        # Brute force detection
        for ip, attempts in failed_logins.items():
            if len(attempts) >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "type": "brute_force",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "attempts": len(attempts),
                    "detail": f"Brute force detected: {len(attempts)} failed logins from {ip}",
                    "mitre": "T1110"
                })

        return alerts

    def _get_mitre(self, pattern_name: str) -> str:
        """Map pattern names to MITRE ATT&CK technique IDs."""
        mapping = {
            "brute_force": "T1110",
            "privilege_esc": "T1548",
            "web_attack": "T1190",
            "recon": "T1595",
            "lateral_movement": "T1021",
        }
        return mapping.get(pattern_name, "T0000")

    def analyze(self, filepath: str) -> dict:
        """Main analysis function."""
        path = Path(filepath)
        if not path.exists():
            print(f"[ERROR] File not found: {filepath}")
            sys.exit(1)

        print(f"\n{'='*60}")
        print(f"  LogForensics — Log Analysis Engine")
        print(f"{'='*60}")
        print(f"  File     : {filepath}")
        print(f"  Size     : {path.stat().st_size / 1024:.1f} KB")
        print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

        parsed_events = []
        total_lines = 0

        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()
            total_lines = len(lines)

            if self.log_type == "auto" and lines:
                sample = " ".join(lines[:5])
                self.log_type = self.detect_log_type(sample)
                print(f"  [*] Detected log type: {self.log_type.upper()}")

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                event = None
                if self.log_type == "linux_auth":
                    event = self.parse_linux_auth(line)
                elif self.log_type == "apache":
                    event = self.parse_apache(line)
                elif self.log_type == "windows":
                    event = self.parse_windows_event(line)
                else:
                    event = {"raw": line}

                if event:
                    parsed_events.append(event)

        print(f"  [*] Parsed {len(parsed_events)}/{total_lines} lines\n")

        alerts = self.detect_anomalies(parsed_events)

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        alerts.sort(key=lambda x: sev_order.get(x["severity"], 9))

        for alert in alerts:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(alert["severity"], "⚪")
            print(f"  {icon} [{alert['severity']}] {alert['type'].upper()} | MITRE: {alert.get('mitre', 'N/A')}")
            print(f"     └─ {alert['detail'][:120]}")
            print()

        return {
            "file": str(filepath),
            "log_type": self.log_type,
            "total_lines": total_lines,
            "parsed_events": len(parsed_events),
            "alerts": alerts,
            "summary": {
                "critical": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
                "high": sum(1 for a in alerts if a["severity"] == "HIGH"),
                "medium": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
            }
        }


def main():
    parser = argparse.ArgumentParser(description="LogForensics - Log Analysis & Anomaly Detection")
    parser.add_argument("-f", "--file", required=True, help="Log file to analyze")
    parser.add_argument("-t", "--type", choices=["auto", "linux_auth", "apache", "windows"],
                        default="auto", help="Log type (default: auto-detect)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    args = parser.parse_args()

    lf = LogParser(log_type=args.type)
    results = lf.analyze(args.file)

    s = results["summary"]
    print(f"{'='*60}")
    print(f"  ANALYSIS COMPLETE")
    print(f"  Critical: {s['critical']} | High: {s['high']} | Medium: {s['medium']}")
    print(f"{'='*60}\n")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"  [+] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
