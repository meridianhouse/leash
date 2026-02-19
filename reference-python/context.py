"""Context Engine — correlates raw events into behavioral sequences.

This is where individual events become stories. A process spawning isn't
interesting. A process spawning a shell that reads SSH keys and opens a
socket IS a story — and it's the story that matters.
"""

from __future__ import annotations
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .models import EventType, SecurityEvent, SystemState, ThreatLevel
from .mitre import MITRE_MAP

log = logging.getLogger("nova.context")

# Time window for correlating related events (seconds)
CORRELATION_WINDOW = 30

# Behavioral patterns — sequences of events that tell a story
ATTACK_PATTERNS = {
    "reverse_shell": {
        "description": "Process establishes outbound connection then spawns shell",
        "sequence": [EventType.NETWORK_SUSPICIOUS, EventType.PROCESS_SHELL_SPAWN],
        "threat_level": ThreatLevel.RED,
        "mitre": "T1059.004",
    },
    "credential_exfil": {
        "description": "Process accesses credentials then makes network connection",
        "sequence": [EventType.CREDENTIAL_ACCESS, EventType.NETWORK_SUSPICIOUS],
        "threat_level": ThreatLevel.RED,
        "mitre": "T1567",
    },
    "persistence_install": {
        "description": "New process creates files in persistence locations",
        "sequence": [EventType.PROCESS_NEW, EventType.FILE_CREATED],
        "threat_level": ThreatLevel.ORANGE,
        "mitre": "T1554",
    },
    "config_tamper_and_connect": {
        "description": "System config modified then new outbound connection",
        "sequence": [EventType.FILE_MODIFIED, EventType.NETWORK_SUSPICIOUS],
        "threat_level": ThreatLevel.ORANGE,
        "mitre": "T1562.001",
    },
    "edr_tamper_and_act": {
        "description": "EDR files modified then suspicious activity",
        "sequence": [EventType.SELF_TAMPER],
        "threat_level": ThreatLevel.RED,
        "mitre": "T1562.001",
    },
    "container_breakout": {
        "description": "Container process detected escaping confinement (namespace/privilege)",
        "sequence": [EventType.CONTAINER_ESCAPE],
        "threat_level": ThreatLevel.RED,
        "mitre": "T1611",
    },
    "vault_theft": {
        "description": "Unauthorized access to credential vault or plaintext secrets found",
        "sequence": [EventType.VAULT_ACCESS],
        "threat_level": ThreatLevel.RED,
        "mitre": "T1555",
    },
}


@dataclass
class BehaviorSequence:
    """A detected behavioral pattern."""
    pattern_name: str
    description: str
    events: list[SecurityEvent]
    threat_level: ThreatLevel
    correlation_strength: str = "strong"
    timestamp: float = field(default_factory=time.time)
    narrative: str = ""
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_name: Optional[str] = None

    def build_narrative(self) -> str:
        """Construct a human-readable story of what happened."""
        parts = [f"⚠️ BEHAVIORAL PATTERN: {self.pattern_name}"]
        if self.mitre_technique:
            parts.append(f"   MITRE: {self.mitre_technique} - {self.mitre_name} ({self.mitre_tactic})")
        parts.append(f"   {self.description}")
        parts.append(f"   Threat Level: {self.threat_level.value.upper()}")
        parts.append(f"   Correlation: {self.correlation_strength.upper()}")
        parts.append("   Event chain:")
        for i, event in enumerate(self.events, 1):
            parts.append(f"   {i}. [{event.event_type.value}] {event.narrative}")
            if event.parent_chain:
                parts.append(f"      Chain: {' → '.join(event.parent_chain)}")
        return "\n".join(parts)


class ContextEngine:
    """Correlates events into behavioral sequences and maintains system narrative."""

    def __init__(self, state: SystemState):
        self.state = state
        self._event_buffer: list[SecurityEvent] = []
        self._detected_sequences: list[BehaviorSequence] = []
        self._pid_event_map: dict[int, list[SecurityEvent]] = defaultdict(list)

    def process_events(self, events: list[SecurityEvent]) -> list[BehaviorSequence]:
        """Process new events, correlate them, detect behavioral patterns."""
        sequences: list[BehaviorSequence] = []

        for event in events:
            self._event_buffer.append(event)
            self.state.add_event(event)

            # Index by PID for per-process correlation
            if event.process:
                self._pid_event_map[event.process.pid].append(event)

            # Log notable events
            if event.threat_level.value != ThreatLevel.GREEN.value:
                log.warning(f"[{event.threat_level.value.upper()}] {event.narrative}")

        # Prune old events from buffer
        cutoff = time.time() - CORRELATION_WINDOW * 2
        self._event_buffer = [e for e in self._event_buffer if e.timestamp > cutoff]

        # Detect behavioral patterns
        sequences.extend(self._detect_patterns())

        # Detect per-PID behavioral anomalies
        sequences.extend(self._detect_pid_anomalies())

        # Detect temporal clustering (many events in short window = suspicious)
        sequences.extend(self._detect_temporal_burst())

        # Keep history of detected sequences
        self._detected_sequences.extend(sequences)

        return sequences

    def _detect_patterns(self) -> list[BehaviorSequence]:
        """Match event sequences against known attack patterns."""
        detected: list[BehaviorSequence] = []
        recent = [e for e in self._event_buffer if time.time() - e.timestamp < CORRELATION_WINDOW]

        for name, pattern in ATTACK_PATTERNS.items():
            sequence_types = pattern["sequence"]
            matched_events: list[SecurityEvent] = []

            # Try to find the sequence in recent events (order matters)
            search_events = list(recent)
            for needed_type in sequence_types:
                found = False
                for i, event in enumerate(search_events):
                    if event.event_type == needed_type:
                        matched_events.append(event)
                        # Remove used event and prior events to enforce order
                        search_events = search_events[i+1:]
                        found = True
                        break
                if not found:
                    break

            if len(matched_events) == len(sequence_types):
                # Analyze correlation strength
                strength = self._analyze_correlation(matched_events)
                
                if strength:
                    # By default, only trigger on STRONG correlations for attack patterns
                    # This reduces false positives from unrelated background noise
                    if strength == "weak":
                        log.debug(f"Skipping weak correlation for pattern {name}")
                        continue
                        
                    seq = BehaviorSequence(
                        pattern_name=name,
                        description=pattern["description"],
                        events=matched_events,
                        threat_level=pattern["threat_level"],
                        correlation_strength=strength,
                    )
                    
                    if "mitre" in pattern:
                        mitre_id = pattern["mitre"]
                        info = MITRE_MAP.get(mitre_id)
                        if info:
                            seq.mitre_technique = mitre_id
                            seq.mitre_tactic = info["tactic"]
                            seq.mitre_name = info["name"]
                    
                    seq.narrative = seq.build_narrative()
                    detected.append(seq)
                    log.critical(f"🚨 PATTERN DETECTED: {name} ({strength.upper()}) — {pattern['description']}")

        return detected

    def _analyze_correlation(self, events: list[SecurityEvent]) -> str | None:
        """Determine correlation strength: strong (PID/parent) vs weak (time-only)."""
        if len(events) < 2:
            return "strong"

        # Check PID/Parent relationships
        pids = set()
        ppids = set()
        events_with_pid = 0
        
        for e in events:
            if e.process:
                events_with_pid += 1
                pids.add(e.process.pid)
                ppids.add(e.process.ppid)
        
        # Case 1: All events have PID info -> Require Strong Correlation
        if events_with_pid == len(events):
            # Same PID?
            if len(pids) == 1:
                return "strong"
            
            # Parent-Child? (One PID is another's PPID)
            if not pids.isdisjoint(ppids):
                return "strong"
                
            # Direct Parent Chain Overlap?
            chains = [set(e.parent_chain) for e in events if e.parent_chain]
            if len(chains) >= 2:
                common = set.intersection(*chains)
                if common:
                    return "strong"

            # If PIDs differ and no relationship found, treat as unrelated
            return None

        # Case 2: Mixed or no PID info (e.g. network/file events) -> Weak Correlation
        timestamps = [e.timestamp for e in events]
        if max(timestamps) - min(timestamps) < 10:
            return "weak"

        return None

    def _detect_pid_anomalies(self) -> list[BehaviorSequence]:
        """Detect suspicious per-process behavior chains."""
        detected: list[BehaviorSequence] = []

        for pid, events in self._pid_event_map.items():
            recent = [e for e in events if time.time() - e.timestamp < CORRELATION_WINDOW]
            if len(recent) < 2:
                continue

            # Check for escalating severity within same PID
            threat_levels = [e.threat_level for e in recent]
            has_credential = any(e.event_type == EventType.CREDENTIAL_ACCESS for e in recent)
            has_network = any(e.event_type in (EventType.NETWORK_NEW_CONN, EventType.NETWORK_SUSPICIOUS) for e in recent)
            has_container = any(e.event_type == EventType.CONTAINER_ESCAPE for e in recent)

            if has_credential and has_network:
                seq = BehaviorSequence(
                    pattern_name="pid_credential_and_network",
                    description=f"PID {pid} accessed credentials AND made network connections",
                    events=recent,
                    threat_level=ThreatLevel.RED,
                    mitre_technique="T1567",
                    mitre_tactic="Exfiltration",
                    mitre_name="Exfiltration Over Web Service"
                )
                seq.narrative = seq.build_narrative()
                detected.append(seq)
            
            if has_container and has_network:
                seq = BehaviorSequence(
                    pattern_name="container_escape_and_c2",
                    description=f"Container escape detected for PID {pid} followed by network activity",
                    events=recent,
                    threat_level=ThreatLevel.NUCLEAR,
                    mitre_technique="T1611",
                    mitre_tactic="Privilege Escalation",
                    mitre_name="Escape to Host"
                )
                seq.narrative = seq.build_narrative()
                detected.append(seq)

        return detected

    def _detect_temporal_burst(self) -> list[BehaviorSequence]:
        """Detect unusual bursts of security events (potential automated attack)."""
        detected: list[BehaviorSequence] = []
        window = 10  # seconds
        recent = [e for e in self._event_buffer
                  if time.time() - e.timestamp < window
                  and e.threat_level.value != ThreatLevel.GREEN.value]

        if len(recent) >= 5:
            seq = BehaviorSequence(
                pattern_name="temporal_burst",
                description=f"{len(recent)} security events in {window}s — possible automated attack",
                events=recent,
                threat_level=ThreatLevel.ORANGE,
                mitre_technique="T1071", # Assuming C2/Flooding? Or just generic.
                mitre_tactic="Command and Control",
                mitre_name="Application Layer Protocol"
            )
            seq.narrative = seq.build_narrative()
            detected.append(seq)

        return detected

    def _events_related(self, events: list[SecurityEvent]) -> bool:
        """Check if events are likely related (same process tree or tight timing)."""
        if len(events) < 2:
            return True

        # Same PID?
        pids = {e.process.pid for e in events if e.process}
        if len(pids) == 1:
            return True

        # Same parent PID?
        ppids = {e.process.ppid for e in events if e.process}
        if len(ppids) == 1:
            return True

        # Within tight time window?
        timestamps = [e.timestamp for e in events]
        if max(timestamps) - min(timestamps) < 10:
            return True

        # Overlapping parent chains?
        chains = [set(e.parent_chain) for e in events if e.parent_chain]
        if len(chains) >= 2:
            if chains[0] & chains[1]:  # Any overlap
                return True

        return False

    def get_system_narrative(self, window_seconds: int = 300) -> str:
        """Generate a narrative summary of recent system activity for AI reasoning."""
        parts = [f"=== System Narrative (last {window_seconds}s) ==="]
        parts.append(f"Overall threat level: {self.state.threat_level.value.upper()}")
        parts.append(f"Active processes: {len(self.state.processes)}")
        parts.append(f"Listen ports: {sorted(self.state.listen_ports) if self.state.listen_ports else 'N/A'}")

        # Recent events
        cutoff = time.time() - window_seconds
        recent = [e for e in self.state.recent_events if e.timestamp > cutoff]
        notable = [e for e in recent if e.threat_level.value != ThreatLevel.GREEN.value]

        if notable:
            parts.append(f"\n--- Notable Events ({len(notable)}) ---")
            for event in notable[-20:]:  # Last 20 notable events
                parts.append(event.to_narrative())
        else:
            parts.append("\nNo notable events.")

        # Detected patterns
        if self._detected_sequences:
            recent_seqs = [s for s in self._detected_sequences if s.timestamp > cutoff]
            if recent_seqs:
                parts.append(f"\n--- Behavioral Patterns Detected ({len(recent_seqs)}) ---")
                for seq in recent_seqs:
                    parts.append(seq.narrative)

        return "\n".join(parts)

    def cleanup(self):
        """Periodic cleanup of old data."""
        cutoff = time.time() - 3600  # 1 hour
        self._event_buffer = [e for e in self._event_buffer if e.timestamp > cutoff]
        for pid in list(self._pid_event_map.keys()):
            self._pid_event_map[pid] = [e for e in self._pid_event_map[pid] if e.timestamp > cutoff]
            if not self._pid_event_map[pid]:
                del self._pid_event_map[pid]
