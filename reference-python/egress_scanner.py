"""Outbound message credential leak detector.

Scans assistant responses in OpenClaw session transcripts for credential
patterns that should NEVER appear in chat messages. Alert-only, never blocks.

Patterns: SSH private keys, API keys (sk-, AKIA, etc.), vault contents,
passwords in common formats.
"""

from __future__ import annotations
import json
import logging
import os
import re
from pathlib import Path
from typing import Generator

from .models import EventType, SecurityEvent, ThreatLevel
from .mitre import tag_event

log = logging.getLogger("nova.egress")

# Patterns that should NEVER appear in outbound messages
CREDENTIAL_PATTERNS = [
    # SSH private keys
    (re.compile(r'-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'), "SSH Private Key"),
    # AWS keys
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key"),
    # OpenAI keys
    (re.compile(r'sk-[a-zA-Z0-9]{20,}'), "OpenAI/API Key (sk-)"),
    # Generic long API tokens (40+ hex chars that look like secrets)
    (re.compile(r'(?:api[_-]?key|token|secret|password)\s*[=:]\s*["\']?[A-Za-z0-9+/=_-]{32,}'), "Inline Credential Assignment"),
    # age encryption keys (vault)
    (re.compile(r'AGE-SECRET-KEY-[A-Z0-9]+'), "age Secret Key"),
    # PGP private key blocks
    (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'), "PGP Private Key"),
    # Generic password patterns in config-like output
    (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{8,}', re.IGNORECASE), "Password in Config"),
    # Telegram bot tokens (specific format)
    (re.compile(r'\d{8,10}:[A-Za-z0-9_-]{35}'), "Telegram Bot Token"),
    # Discord bot tokens
    (re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}'), "Discord Bot Token"),
]

# How many bytes from end of file to read each scan (avoid reading entire history)
TAIL_BYTES = 50_000  # ~50KB covers recent messages


class EgressScanner:
    """Scans outbound assistant messages for credential leaks."""

    def __init__(self, sessions_dir: Path | None = None):
        self.sessions_dir = sessions_dir or (Path.home() / ".openclaw" / "agents" / "main" / "sessions")
        # Track file positions so we only scan new content
        self._file_positions: dict[str, int] = {}

    def collect(self) -> list[SecurityEvent]:
        """Scan recent assistant messages for credential patterns."""
        events: list[SecurityEvent] = []

        if not self.sessions_dir.exists():
            return events

        # Find the most recently modified session files (only check active ones)
        try:
            session_files = sorted(
                self.sessions_dir.glob("*.jsonl"),
                key=lambda f: f.stat().st_mtime,
                reverse=True
            )[:3]  # Only check 3 most recent sessions
        except OSError:
            return events

        for session_file in session_files:
            try:
                events.extend(self._scan_session(session_file))
            except Exception as e:
                log.warning(f"Egress scan error on {session_file}: {e}")

        return events

    def _scan_session(self, path: Path) -> list[SecurityEvent]:
        """Scan new content in a session file."""
        events: list[SecurityEvent] = []
        file_key = str(path)

        try:
            file_size = path.stat().st_size
        except OSError:
            return events

        # Get last known position
        last_pos = self._file_positions.get(file_key, 0)

        # If file hasn't grown, skip
        if file_size <= last_pos:
            return events

        # Read only new content (or tail if first time)
        start_pos = last_pos if last_pos > 0 else max(0, file_size - TAIL_BYTES)

        try:
            with open(path, 'r', errors='ignore') as f:
                f.seek(start_pos)
                # If we seeked to middle of file, skip partial first line
                if start_pos > 0:
                    f.readline()

                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        msg = record.get("message", {})

                        # Only scan assistant messages (outbound)
                        if msg.get("role") != "assistant":
                            continue

                        content = msg.get("content", "")
                        if isinstance(content, list):
                            # Extract text from content blocks
                            text_parts = []
                            for block in content:
                                if isinstance(block, dict):
                                    if block.get("type") == "text":
                                        text_parts.append(block.get("text", ""))
                            content = "\n".join(text_parts)
                        elif not isinstance(content, str):
                            continue

                        # Scan for credential patterns
                        for pattern, label in CREDENTIAL_PATTERNS:
                            match = pattern.search(content)
                            if match:
                                # Get a safe snippet (redact the actual match)
                                snippet_start = max(0, match.start() - 20)
                                snippet_end = min(len(content), match.end() + 20)
                                snippet = content[snippet_start:snippet_end]
                                # Redact the matched value
                                matched_text = match.group(0)
                                redacted = matched_text[:6] + "..." + matched_text[-4:] if len(matched_text) > 12 else "REDACTED"

                                events.append(tag_event(SecurityEvent(
                                    event_type=EventType.CREDENTIAL_ACCESS,
                                    threat_level=ThreatLevel.RED,
                                    narrative=(
                                        f"🚨 CREDENTIAL LEAK IN OUTBOUND MESSAGE: {label} detected in assistant response. "
                                        f"Value: {redacted}. Session: {path.stem}. "
                                        f"This may indicate prompt injection or accidental credential exposure."
                                    ),
                                ), "T1048.003"))

                                log.critical(f"EGRESS LEAK DETECTED: {label} in {path.name}")
                                break  # One alert per message is enough

                    except json.JSONDecodeError:
                        continue

            # Update position
            self._file_positions[file_key] = file_size

        except (PermissionError, OSError) as e:
            log.warning(f"Cannot read session file {path}: {e}")

        return events
