"""Data models for Nova EDR events and system state."""

from __future__ import annotations
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ThreatLevel(Enum):
    GREEN = "green"      # Normal
    YELLOW = "yellow"    # Suspicious — alert + forensics
    ORANGE = "orange"    # Likely malicious — kill process
    RED = "red"          # Confirmed threat — contain
    NUCLEAR = "nuclear"  # Active exfil — kill network

    @property
    def severity(self) -> int:
        order = {
            "green": 0,
            "yellow": 1,
            "orange": 2,
            "red": 3,
            "nuclear": 4
        }
        return order.get(self.value, 0)
    
    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.severity < other.severity
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.severity > other.severity
        return NotImplemented
    
    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.severity <= other.severity
        return NotImplemented

    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.severity >= other.severity
        return NotImplemented


class EventType(Enum):
    PROCESS_NEW = "process_new"
    PROCESS_EXIT = "process_exit"
    PROCESS_SHELL_SPAWN = "process_shell_spawn"
    NETWORK_NEW_CONN = "network_new_connection"
    NETWORK_NEW_LISTEN = "network_new_listen"
    NETWORK_SUSPICIOUS = "network_suspicious"
    FILE_MODIFIED = "file_modified"
    FILE_CREATED = "file_created"
    FILE_PERMISSION_CHANGE = "file_permission_change"
    CREDENTIAL_ACCESS = "credential_access"
    SELF_TAMPER = "self_tamper"
    PERSISTENCE = "persistence"
    CONTAINER_ESCAPE = "container_escape"
    VAULT_ACCESS = "vault_access"


@dataclass
class ProcessInfo:
    """Snapshot of a running process."""
    pid: int
    ppid: int
    name: str
    cmdline: str
    username: str
    create_time: float
    exe: str = ""
    cwd: str = ""
    connections: list[NetConnection] = field(default_factory=list)
    open_files: list[str] = field(default_factory=list)
    children: list[int] = field(default_factory=list)
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    status: str = ""
    cgroup: list[str] = field(default_factory=list)
    namespaces: dict[str, str] = field(default_factory=dict)

    @property
    def age_seconds(self) -> float:
        return time.time() - self.create_time

    @property
    def parent_chain(self) -> str:
        """Will be populated by context engine with full ancestry."""
        return ""

    def to_narrative(self) -> str:
        """Human-readable description for AI consumption."""
        parts = [f"Process '{self.name}' (PID {self.pid})"]
        parts.append(f"  cmd: {self.cmdline}")
        parts.append(f"  user: {self.username}, parent PID: {self.ppid}")
        if self.exe:
            parts.append(f"  exe: {self.exe}")
        if self.cwd:
            parts.append(f"  cwd: {self.cwd}")
        if self.cgroup:
            parts.append(f"  cgroups: {self.cgroup[:2]}...")  # Show first 2 cgroups
        if self.namespaces:
            parts.append(f"  namespaces: {len(self.namespaces)}")
        if self.connections:
            parts.append(f"  connections: {len(self.connections)}")
            for conn in self.connections[:5]:
                parts.append(f"    {conn}")
        if self.open_files:
            sensitive = [f for f in self.open_files if any(
                s in f for s in ['.ssh', '.gnupg', 'vault', 'secret', 'token', 'credential', '.env']
            )]
            if sensitive:
                parts.append(f"  ⚠️ SENSITIVE FILES OPEN: {sensitive}")
        return "\n".join(parts)


@dataclass
class NetConnection:
    """A network connection."""
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    pid: int
    process_name: str = ""

    def __str__(self) -> str:
        if self.remote_addr:
            return f"{self.local_addr}:{self.local_port} → {self.remote_addr}:{self.remote_port} ({self.status})"
        return f"LISTEN {self.local_addr}:{self.local_port}"


@dataclass
class FileEvent:
    """A filesystem change event."""
    path: str
    event_type: str  # modified, created, deleted, permission_changed
    timestamp: float = field(default_factory=time.time)
    old_hash: str = ""
    new_hash: str = ""
    old_perms: str = ""
    new_perms: str = ""


@dataclass
class SecurityEvent:
    """A correlated security event ready for AI analysis."""
    event_type: EventType
    timestamp: float = field(default_factory=time.time)
    threat_level: ThreatLevel = ThreatLevel.GREEN
    process: Optional[ProcessInfo] = None
    connection: Optional[NetConnection] = None
    file_event: Optional[FileEvent] = None
    narrative: str = ""
    parent_chain: list[str] = field(default_factory=list)
    related_events: list[SecurityEvent] = field(default_factory=list)
    ai_analysis: str = ""
    response_taken: str = ""
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_name: Optional[str] = None

    def to_narrative(self) -> str:
        """Full narrative for AI reasoning."""
        parts = [f"[{self.event_type.value}] @ {time.strftime('%H:%M:%S', time.localtime(self.timestamp))}"]
        if self.mitre_technique:
            parts.append(f"MITRE: {self.mitre_technique} - {self.mitre_name} ({self.mitre_tactic})")
        if self.narrative:
            parts.append(self.narrative)
        if self.process:
            parts.append(self.process.to_narrative())
        if self.connection:
            parts.append(f"  Connection: {self.connection}")
        if self.file_event:
            parts.append(f"  File: {self.file_event.path} ({self.file_event.event_type})")
        if self.parent_chain:
            parts.append(f"  Process chain: {' → '.join(self.parent_chain)}")
        return "\n".join(parts)


@dataclass
class SystemState:
    """The AI's mental model of the current system."""
    processes: dict[int, ProcessInfo] = field(default_factory=dict)
    connections: list[NetConnection] = field(default_factory=list)
    listen_ports: set[int] = field(default_factory=set)
    file_hashes: dict[str, str] = field(default_factory=dict)
    known_good_processes: set[str] = field(default_factory=set)
    known_good_connections: set[str] = field(default_factory=set)
    recent_events: list[SecurityEvent] = field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.GREEN
    last_update: float = field(default_factory=time.time)
    learning_mode: bool = False

    def add_event(self, event: SecurityEvent):
        self.recent_events.append(event)
        # Keep last 1000 events
        if len(self.recent_events) > 1000:
            self.recent_events = self.recent_events[-1000:]
        # Escalate threat level if needed
        if event.threat_level > self.threat_level:
            self.threat_level = event.threat_level
        self.last_update = time.time()

    def get_narrative_window(self, seconds: int = 300) -> str:
        """Get recent events as a narrative for AI consumption."""
        cutoff = time.time() - seconds
        recent = [e for e in self.recent_events if e.timestamp > cutoff]
        if not recent:
            return f"No notable events in the last {seconds} seconds."
        return "\n---\n".join(e.to_narrative() for e in recent)
