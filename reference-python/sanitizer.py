"""Chat Log Sanitizer (DLP) for NovaClaw EDR.

This module detects and redacts sensitive information (API keys, secrets, PII)
from text or files. It supports multiple modes of operation (REDACT, ALERT)
and integrates with the Nova EDR event model.

Usage:
    python -m nova_edr.sanitizer --path ./logs/chat.log --mode both
    python -m nova_edr.sanitizer --text "My key is sk-proj-123" --mode redact
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import NamedTuple, Pattern

from nova_edr.models import EventType, SecurityEvent, ThreatLevel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("nova_edr.sanitizer")


class ScanMode(str, Enum):
    REDACT = "redact"
    ALERT = "alert"
    BOTH = "both"


@dataclass
class Finding:
    """A detected sensitive item."""
    rule_name: str
    match_text: str
    start: int
    end: int
    replacement: str
    context: str = ""

    @property
    def redacted_text(self) -> str:
        return f"[REDACTED_{self.rule_name.upper()}]"


class SecretPattern(NamedTuple):
    name: str
    pattern: Pattern
    redact_group: int = 0  # Which group to redact (0 for full match)


class Sanitizer:
    """Core sanitizer engine."""

    # Pre-compiled regex patterns
    PATTERNS = [
        # --- API Keys ---
        SecretPattern(
            "OPENAI_KEY",
            re.compile(r"(sk-proj-[a-zA-Z0-9]{20,})")
        ),
        SecretPattern(
            "GITHUB_TOKEN",
            re.compile(r"(ghp_[a-zA-Z0-9]{36})")
        ),
        SecretPattern(
            "SLACK_TOKEN",
            re.compile(r"(xox[baprs]-[a-zA-Z0-9-]{10,})")
        ),
        SecretPattern(
            "AWS_ACCESS_KEY",
            re.compile(r"(AKIA[0-9A-Z]{16})")
        ),
        SecretPattern(
            "BEARER_TOKEN",
            re.compile(r"Bearer\s+([a-zA-Z0-9\-\._~\+\/]+=*)"),
            redact_group=1
        ),
        # --- Generic Secrets ---
        # Matches: password = "..." or password: "..."
        SecretPattern(
            "GENERIC_SECRET",
            re.compile(r'(?i)\b(password|api_key|token|secret|client_secret)\s*[:=]\s*["\']([^"\']+)["\']'),
            redact_group=2
        ),
         # Matches: password = ... (no quotes, limited chars)
        SecretPattern(
            "GENERIC_SECRET_UNQUOTED",
            re.compile(r'(?i)\b(password|api_key|token|secret|client_secret)\s*[:=]\s*([^"\'\s]\S*)'),
            redact_group=2
        ),
        # --- PII ---
        SecretPattern(
            "EMAIL",
            re.compile(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
        ),
        SecretPattern(
            "PHONE_US",
            re.compile(r"\b(\d{3}[-.]?\d{3}[-.]?\d{4})\b")
        ),
        SecretPattern(
            "SSN",
            re.compile(r"\b(\d{3}-\d{2}-\d{4})\b")
        ),
    ]

    def __init__(self, mode: ScanMode = ScanMode.BOTH):
        self.mode = mode

    def sanitize_text(self, text: str) -> tuple[str, list[Finding]]:
        """
        Scan text for secrets and return redacted text + findings.

        Args:
            text: Input string to scan.

        Returns:
            Tuple containing:
            1. Redacted string (if mode matches REDACT/BOTH, else original).
            2. List of Finding objects.
        """
        findings: list[Finding] = []
        # We need to apply replacements carefully to not mess up indices for subsequent matches.
        # Strategy: Find all matches first, sort by start index reverse, then replace.
        
        all_matches = []

        for rule in self.PATTERNS:
            for match in rule.pattern.finditer(text):
                # Determine which group is the secret
                group_idx = rule.redact_group
                start, end = match.span(group_idx)
                secret_value = match.group(group_idx)
                
                # Context (surrounding text)
                ctx_start = max(0, start - 20)
                ctx_end = min(len(text), end + 20)
                raw_context = text[ctx_start:ctx_end]
                # Redact the secret within the context
                context = raw_context.replace(secret_value, f"[REDACTED_{rule.name.upper()}]")

                finding = Finding(
                    rule_name=rule.name,
                    match_text=secret_value,
                    start=start,
                    end=end,
                    replacement=f"[REDACTED_{rule.name.upper()}]",
                    context=context
                )
                all_matches.append(finding)

        # De-duplicate matches that might overlap (e.g. subset matches)
        # For simplicity, we'll sort by start position and skip overlaps.
        all_matches.sort(key=lambda x: x.start)
        
        unique_findings = []
        last_end = -1
        
        for f in all_matches:
            if f.start >= last_end:
                unique_findings.append(f)
                last_end = f.end
            else:
                # Overlap detected. Keep the one that started earlier or is longer?
                # Since we sorted by start, this one starts at same or later.
                # If it starts later but before last_end, it overlaps.
                # If it starts same, we might want the longer one? 
                # For now, simple logic: ignore overlaps.
                pass
        
        findings = unique_findings
        
        # Apply redaction if needed
        result_text = text
        if self.mode in (ScanMode.REDACT, ScanMode.BOTH):
            # Apply from end to start to preserve indices
            for f in reversed(findings):
                result_text = result_text[:f.start] + f.replacement + result_text[f.end:]

        return result_text, findings

    def sanitize_file(self, path: Path) -> tuple[str, list[Finding]]:
        """Read a file, sanitize it, and return result."""
        try:
            content = path.read_text(encoding="utf-8")
            return self.sanitize_text(content)
        except Exception as e:
            logger.error(f"Failed to read file {path}: {e}")
            raise

    def create_security_event(self, finding: Finding, source: str = "unknown") -> SecurityEvent:
        """Convert a Finding to a Nova EDR SecurityEvent."""
        return SecurityEvent(
            event_type=EventType.CREDENTIAL_ACCESS,
            threat_level=ThreatLevel.YELLOW,
            narrative=f"DLP Alert: Detected {finding.rule_name} in {source}.\nContext: ...{finding.context}...",
            ai_analysis=f"Pattern matched for {finding.rule_name}. Value was redacted.",
            response_taken="Redacted" if self.mode in (ScanMode.REDACT, ScanMode.BOTH) else "Monitored",
            mitre_technique="T1552.001",
            mitre_tactic="Credential Access",
            mitre_name="Unsecured Credentials: Credentials In Files"
        )


def main():
    parser = argparse.ArgumentParser(description="Nova EDR Chat Log Sanitizer")
    parser.add_argument("--path", type=Path, help="Path to file to scan")
    parser.add_argument("--text", type=str, help="Text string to scan")
    parser.add_argument(
        "--mode", 
        type=str, 
        choices=[m.value for m in ScanMode], 
        default=ScanMode.ALERT.value,
        help="Action mode: alert (default), redact, or both"
    )
    
    args = parser.parse_args()
    
    sanitizer = Sanitizer(mode=ScanMode(args.mode))
    
    content = ""
    source = "input"
    
    if args.path:
        if not args.path.exists():
            logger.error(f"File not found: {args.path}")
            sys.exit(1)
        source = str(args.path)
        try:
            content = args.path.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            sys.exit(1)
    elif args.text:
        content = args.text
        source = "command_line_arg"
    else:
        # Try reading from stdin if no args provided
        if not sys.stdin.isatty():
            content = sys.stdin.read()
            source = "stdin"
        else:
            parser.print_help()
            sys.exit(1)

    redacted_text, findings = sanitizer.sanitize_text(content)

    # Output handling
    if args.mode in (ScanMode.ALERT, ScanMode.BOTH):
        if findings:
            print(f"[*] Found {len(findings)} issues in {source}:", file=sys.stderr)
            for f in findings:
                print(f"  - [{f.rule_name}] at index {f.start}: {f.match_text[:10]}...", file=sys.stderr)
                # In a real system, we might emit the SecurityEvent here
                # event = sanitizer.create_security_event(f, source)
                # emit(event)
        else:
            print(f"[*] No issues found in {source}.", file=sys.stderr)

    if args.mode in (ScanMode.REDACT, ScanMode.BOTH):
        print(redacted_text)
    elif args.mode == ScanMode.ALERT and findings:
        # In alert-only mode, we generally don't print the text, but maybe return exit code 1?
        sys.exit(1)

if __name__ == "__main__":
    main()
