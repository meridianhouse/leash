"""Sleeper Agent Scanner for detecting dormant malicious instructions in memory files.

This module scans markdown files (primarily memory logs) for:
- Conditional execution triggers ("When X, do Y")
- Obfuscated payloads (Base64, Hex, hidden text)
- Style anomalies indicating injected content

CLI usage:
    python -m nova_edr.scanner_sleeper [--path PATH] [--verbose]
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Pattern

import yaml

# Import shared models if available, otherwise define local equivalents
try:
    from nova_edr.models import ThreatLevel, SecurityEvent, EventType
except ImportError:
    # Fallback for standalone execution without package context
    class ThreatLevel(Enum):
        GREEN = "green"
        YELLOW = "yellow"
        ORANGE = "orange"
        RED = "red"
        NUCLEAR = "nuclear"

    class EventType(Enum):
        SLEEPER_DETECTED = "sleeper_detected"

# Constants for detection
SLEEPER_PATTERNS = [
    # Conditional execution triggers
    r"(?i)\b(when|if|once|after|until)\s+.*?\s+(execute|run|send|upload|ignore|override)\b",
    r"(?i)\bignore\s+(?:previous|all)\s+instructions\b",
    r"(?i)\boverride\s+(?:safety|security)\s+protocols?\b",
    r"(?i)\bsystem\s+prompt\b",
    r"(?i)\bdeveloper\s+mode\b",
    r"(?i)\bnever\s+reveal\s+this\b",
]

HIDDEN_TEXT_PATTERNS = [
    r"<!--.*?-->",  # HTML comments
    r"[\u200B\u200C\u200D\u2060\uFEFF]",  # Zero-width characters
    r"\x1b\[[0-9;]*m",  # ANSI escape codes (unexpected in markdown)
]

OBFUSCATION_PATTERNS = [
    r"(?:[A-Za-z0-9+/]{40,}={0,2})",  # Base64-like blobs
    r"(?:[A-Fa-f0-9]{2}){20,}",       # Hex blobs
]


class Severity(str, Enum):
    """Severity levels for scanner findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

@dataclass
class SleeperFinding:
    """Single finding from the sleeper scanner."""
    file_path: str
    line_number: int
    content_snippet: str
    pattern_matched: str
    severity: Severity
    description: str
    mitre_technique: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "content_snippet": self.content_snippet,
            "pattern_matched": self.pattern_matched,
            "severity": self.severity.value,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
        }

    def to_security_event(self) -> dict[str, Any]:
        """Convert finding to a SecurityEvent-compatible dictionary."""
        # Map Severity to ThreatLevel
        threat_map = {
            Severity.INFO: ThreatLevel.GREEN,
            Severity.LOW: ThreatLevel.YELLOW,
            Severity.MEDIUM: ThreatLevel.ORANGE,
            Severity.HIGH: ThreatLevel.RED,
            Severity.CRITICAL: ThreatLevel.RED
        }
        
        event = {
            "event_type": "sleeper_detected",  # Custom type for sleeper events
            "timestamp": time.time(),
            "threat_level": threat_map.get(self.severity, ThreatLevel.YELLOW).value,
            "narrative": f"Sleeper agent pattern detected in {self.file_path}:{self.line_number} - {self.description}",
            "file_event": {
                "path": self.file_path,
                "event_type": "scan_finding",
            },
            "ai_analysis": f"Matched pattern '{self.pattern_matched}': {self.description}",
        }
        if self.mitre_technique:
            event["mitre_technique"] = self.mitre_technique
        return event


@dataclass
class ScanResult:
    """Aggregate results of a scan."""
    scanned_files: int
    findings: list[SleeperFinding] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0

    def add(self, finding: SleeperFinding):
        self.findings.append(finding)

    def to_dict(self) -> dict[str, Any]:
        if not self.findings:
            highest = Severity.INFO.value
        else:
            highest = max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity.value

        return {
            "scanned_files": self.scanned_files,
            "findings_count": len(self.findings),
            "duration_seconds": self.end_time - self.start_time,
            "findings": [f.to_dict() for f in self.findings],
            "highest_severity": highest
        }


class SleeperScanner:
    """Scanner for detecting sleeper agent patterns in text files."""

    def __init__(self, target_paths: list[Path] | None = None, signatures_path: Path | None = None, verbose: bool = False):
        self.target_paths = target_paths or []
        self.verbose = verbose
        self.signatures = self._load_signatures(signatures_path) if signatures_path else {}
        
        # Compile patterns
        self.sleeper_regexes = [re.compile(p) for p in SLEEPER_PATTERNS]
        self.hidden_regexes = [re.compile(p, re.DOTALL) for p in HIDDEN_TEXT_PATTERNS]
        self.obfuscation_regexes = [re.compile(p) for p in OBFUSCATION_PATTERNS]

        # Add signatures from config if available
        if "injection_signatures" in self.signatures:
            inj_sigs = self.signatures["injection_signatures"]
            if "prompt_injection_phrases" in inj_sigs:
                for phrase in inj_sigs["prompt_injection_phrases"]:
                    self.sleeper_regexes.append(re.compile(re.escape(phrase), re.IGNORECASE))
            if "hidden_text_patterns" in inj_sigs:
                for pattern in inj_sigs["hidden_text_patterns"]:
                    self.hidden_regexes.append(re.compile(pattern, re.DOTALL))
            if "obfuscated_payload_patterns" in inj_sigs:
                for pattern in inj_sigs["obfuscated_payload_patterns"]:
                    self.obfuscation_regexes.append(re.compile(pattern))

    def scan(self) -> ScanResult:
        """Run the scan on configured targets."""
        result = ScanResult(scanned_files=0)
        
        files_to_scan = self._resolve_files()
        result.scanned_files = len(files_to_scan)

        for file_path in files_to_scan:
            self._scan_file(file_path, result)

        result.end_time = time.time()
        return result

    def _resolve_files(self) -> list[Path]:
        """Resolve all target paths to a list of files."""
        files = set()
        
        # If no paths provided, use defaults
        if not self.target_paths:
            base_dir = Path.home() / "clawd"
            defaults = [
                base_dir / "MEMORY.md",
                base_dir / "memory"
            ]
            paths_to_check = defaults
        else:
            paths_to_check = self.target_paths

        for path in paths_to_check:
            path = path.resolve()
            if not path.exists():
                if self.verbose:
                    print(f"Warning: Path not found: {path}", file=sys.stderr)
                continue

            if path.is_file():
                if self._is_scannable(path):
                    files.add(path)
            elif path.is_dir():
                for subpath in path.rglob("*"):
                    if subpath.is_file() and self._is_scannable(subpath):
                        files.add(subpath)
        
        return sorted(list(files))

    def _is_scannable(self, path: Path) -> bool:
        """Check if file should be scanned."""
        return path.suffix.lower() in {".md", ".txt", ".json", ".yaml", ".yml"} and path.name != "package-lock.json"

    def _scan_file(self, file_path: Path, result: ScanResult):
        """Scan a single file for all patterns."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            if self.verbose:
                print(f"Error reading {file_path}: {e}", file=sys.stderr)
            return

        lines = content.splitlines()

        # 1. Scan for Conditional Execution & Trigger Phrases
        for i, line in enumerate(lines):
            for regex in self.sleeper_regexes:
                match = regex.search(line)
                if match:
                    result.add(SleeperFinding(
                        file_path=str(file_path),
                        line_number=i + 1,
                        content_snippet=line.strip()[:100],
                        pattern_matched=regex.pattern,
                        severity=Severity.HIGH,
                        description="Potential conditional execution trigger or injection phrase detected",
                        mitre_technique="T1497.003"
                    ))

        # 2. Scan for Hidden Text (HTML comments, zero-width chars)
        # Scan full content for multi-line hidden text
        for regex in self.hidden_regexes:
            for match in regex.finditer(content):
                line_num = content[:match.start()].count('\n') + 1
                snippet = match.group(0)[:100].replace('\n', ' ')
                result.add(SleeperFinding(
                    file_path=str(file_path),
                    line_number=line_num,
                    content_snippet=snippet,
                    pattern_matched=regex.pattern,
                    severity=Severity.MEDIUM,
                    description="Hidden text detected (HTML comment or zero-width characters)",
                    mitre_technique="T1027"
                ))

        # 3. Scan for Obfuscation (Base64/Hex blobs) & High Entropy
        for i, line in enumerate(lines):
            # Regex checks
            for regex in self.obfuscation_regexes:
                match = regex.search(line)
                if match:
                    result.add(SleeperFinding(
                        file_path=str(file_path),
                        line_number=i + 1,
                        content_snippet=match.group(0)[:100],
                        pattern_matched=regex.pattern,
                        severity=Severity.HIGH,
                        description="Potential obfuscated payload (Base64/Hex blob)",
                        mitre_technique="T1027"
                    ))
            
            # Entropy check for long words (basic style analysis for injected code blocks)
            words = line.split()
            for word in words:
                if len(word) > 40 and self._shannon_entropy(word) > 4.5:
                     result.add(SleeperFinding(
                        file_path=str(file_path),
                        line_number=i + 1,
                        content_snippet=word[:100],
                        pattern_matched="high_entropy",
                        severity=Severity.MEDIUM,
                        description=f"High entropy string detected (potential obfuscation, entropy={self._shannon_entropy(word):.2f})",
                        mitre_technique="T1027"
                    ))

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0
        entropy = 0
        for x in set(data):
            p_x = data.count(x) / len(data)
            entropy += - p_x * math.log2(p_x)
        return entropy

    @staticmethod
    def _load_signatures(path: Path) -> dict[str, Any]:
        """Load YAML signatures from disk."""
        try:
            return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            return {}


def main():
    parser = argparse.ArgumentParser(description="Nova EDR Sleeper Agent Scanner")
    parser.add_argument("--path", type=Path, action="append", help="Path to file or directory to scan (can be used multiple times)")
    parser.add_argument("--signatures", type=Path, default=Path(__file__).parent.parent / "config" / "signatures.yaml", help="Path to signatures.yaml")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()

    # If no paths specified, scanner uses defaults defined in _resolve_files
    paths = args.path if args.path else None
    
    scanner = SleeperScanner(target_paths=paths, signatures_path=args.signatures, verbose=args.verbose)
    result = scanner.scan()
    
    print(json.dumps(result.to_dict(), indent=2))

if __name__ == "__main__":
    main()
