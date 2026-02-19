"""MITRE ATT&CK Framework Mapping for NovaClaw EDR.

Provides tagging utilities and coverage reporting.
"""

from __future__ import annotations
import argparse
import sys
from typing import Optional

from .models import SecurityEvent

# Full mapping based on MITRE-MAPPING.md
MITRE_MAP = {
    # Execution
    "T1059.004": {"tactic": "Execution", "name": "Command and Scripting Interpreter: Unix Shell", "active": True},
    "T1059.006": {"tactic": "Execution", "name": "Command and Scripting Interpreter: Python", "active": True},
    "T1204": {"tactic": "Execution", "name": "User Execution", "active": True},
    "T1204.003": {"tactic": "Execution", "name": "User Execution: Malicious Image", "active": False},

    # Persistence
    "T1554": {"tactic": "Persistence", "name": "Compromise Client Software Binary", "active": True},
    "T1098": {"tactic": "Persistence", "name": "Account Manipulation", "active": False},
    "T1195.001": {"tactic": "Initial Access", "name": "Supply Chain Compromise: Compromise Software Dependencies", "active": True},
    "T1566": {"tactic": "Initial Access", "name": "Phishing", "active": True},

    # Privilege Escalation
    "T1548": {"tactic": "Privilege Escalation", "name": "Abuse Elevation Control Mechanism", "active": False},
    "T1548.003": {"tactic": "Privilege Escalation", "name": "Abuse Elevation Control Mechanism: Sudo Caching", "active": False},
    "T1611": {"tactic": "Privilege Escalation", "name": "Escape to Host", "active": True},

    # Defense Evasion
    "T1027": {"tactic": "Defense Evasion", "name": "Obfuscated Files or Information", "active": True},
    "T1497": {"tactic": "Defense Evasion", "name": "Virtualization/Sandbox Evasion", "active": True},
    "T1497.003": {"tactic": "Defense Evasion", "name": "Virtualization/Sandbox Evasion: Time-Based Evasion", "active": True},
    "T1070": {"tactic": "Defense Evasion", "name": "Indicator Removal", "active": True},
    "T1036": {"tactic": "Defense Evasion", "name": "Masquerading", "active": False},
    "T1562.001": {"tactic": "Defense Evasion", "name": "Impair Defenses: Disable or Modify Tools", "active": True},
    "T1134": {"tactic": "Defense Evasion", "name": "Access Token Manipulation", "active": False},
    "T1609": {"tactic": "Defense Evasion", "name": "Container Administration Command", "active": False},

    # Credential Access
    "T1552.001": {"tactic": "Credential Access", "name": "Unsecured Credentials: Credentials In Files", "active": True},
    "T1555": {"tactic": "Credential Access", "name": "Credentials from Password Stores", "active": True},

    # Collection
    "T1005": {"tactic": "Collection", "name": "Data from Local System", "active": True},
    "T1213": {"tactic": "Collection", "name": "Data from Information Repositories", "active": False},

    # Command and Control
    "T1071": {"tactic": "Command and Control", "name": "Application Layer Protocol", "active": True},
    "T1043": {"tactic": "Command and Control", "name": "Commonly Used Port", "active": True},

    # Exfiltration
    "T1041": {"tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel", "active": True},
    "T1567": {"tactic": "Exfiltration", "name": "Exfiltration Over Web Service", "active": True},
    "T1048": {"tactic": "Exfiltration", "name": "Exfiltration Over Alternative Protocol", "active": True},

    # Impact
    "T1496": {"tactic": "Impact", "name": "Resource Hijacking", "active": False},
    "T1565.001": {"tactic": "Impact", "name": "Stored Data Manipulation", "active": False},
    "T1485": {"tactic": "Impact", "name": "Data Destruction", "active": False},
    "T1491": {"tactic": "Impact", "name": "Defacement", "active": False},
    "T1578": {"tactic": "Impact", "name": "Modify Cloud Compute Infrastructure", "active": False},
}


def tag_event(event: SecurityEvent, technique_id: str) -> SecurityEvent:
    """Enrich a SecurityEvent with MITRE ATT&CK metadata."""
    if technique_id in MITRE_MAP:
        info = MITRE_MAP[technique_id]
        event.mitre_technique = technique_id
        event.mitre_tactic = info["tactic"]
        event.mitre_name = info["name"]
    return event


def print_coverage():
    """Print a table of current detection coverage."""
    print("NovaClaw EDR - MITRE ATT&CK Coverage Report")
    print("=" * 100)
    print(f"{'ID':<12} | {'Status':<10} | {'Tactic':<20} | {'Name'}")
    print("-" * 100)
    
    # Sort by tactic then ID
    sorted_map = sorted(MITRE_MAP.items(), key=lambda x: (x[1]['tactic'], x[0]))
    
    current_tactic = ""
    for tid, info in sorted_map:
        if info['tactic'] != current_tactic:
            print("-" * 100)
            current_tactic = info['tactic']
        
        status = "✅ ACTIVE" if info['active'] else "❌ GAP"
        print(f"{tid:<12} | {status:<10} | {info['tactic']:<20} | {info['name']}")
    
    print("=" * 100)
    active_count = sum(1 for i in MITRE_MAP.values() if i['active'])
    print(f"Total Techniques Covered: {len(MITRE_MAP)}")
    print(f"Active Monitoring: {active_count} / {len(MITRE_MAP)} ({active_count/len(MITRE_MAP)*100:.1f}%)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nova EDR MITRE Tool")
    parser.add_argument("--coverage", action="store_true", help="Show detection coverage report")
    args = parser.parse_args()

    if args.coverage:
        print_coverage()
    else:
        parser.print_help()
