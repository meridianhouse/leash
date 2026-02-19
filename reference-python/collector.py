"""Telemetry collectors — pure Python, zero AI cost.

Collects process, network, and file integrity data from the system.
Produces raw events for the context engine to correlate.
"""

from __future__ import annotations
import hashlib
import logging
import os
import re
import time
import json
from pathlib import Path
from typing import Generator

import psutil

from .models import (
    EventType, FileEvent, NetConnection, ProcessInfo, SecurityEvent,
    SystemState, ThreatLevel,
)
from .sanitizer import Sanitizer, ScanMode
from .mitre import tag_event

log = logging.getLogger("nova.collector")

# Shells and interpreters that can execute arbitrary code
SHELL_BINARIES = {"bash", "sh", "zsh", "dash", "fish", "csh", "tcsh", "ksh"}
INTERPRETER_BINARIES = {"python", "python3", "python3.13", "node", "ruby", "perl", "php"}
SUSPICIOUS_TOOLS = {"nc", "ncat", "netcat", "socat", "nmap", "masscan", "curl", "wget", "docker", "kubectl"}

# Sensitive file paths to monitor
VAULT_PATH = Path.home() / ".clawdbot" / "secrets" / "vault"
SENSITIVE_PATHS = [
    Path.home() / ".ssh",
    Path.home() / ".gnupg",
    Path.home() / ".clawdbot" / "secrets",
    VAULT_PATH,
    Path.home() / ".config",
    Path("/etc/passwd"),
    Path("/etc/shadow"),
    Path("/etc/sudoers"),
    Path("/etc/crontab"),
    Path("/var/spool/cron"),
    Path.home() / ".bashrc",
    Path.home() / ".profile",
    Path.home() / ".bash_profile",
    Path.home() / ".zshrc",
]

# Known reverse shell ports
SUSPICIOUS_PORTS = {4444, 4445, 5555, 6666, 7777, 8888, 9999, 1337, 31337}

# Whitelisted LAN subnets — connections to these are trusted (e.g. Mac ↔ Alienware transfers)
import ipaddress
TRUSTED_LAN_NETS = [
    ipaddress.ip_network("192.168.147.0/24"),
    ipaddress.ip_network("127.0.0.0/8"),
]

def _is_trusted_lan(ip: str) -> bool:
    """Return True if ip falls within a trusted LAN subnet."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in TRUSTED_LAN_NETS)
    except ValueError:
        return False

# Directories to exclude from recursive scanning to prevent DoS
EXCLUDED_DIRS = {
    '.cache', 'Google', 'Slack', 'Code', 'chromium', 'discord', 'spotify',
    'BraveSoftware', 'Cache', 'CacheStorage', 'GPUCache', 'ShaderCache'
}

# Persistence locations
PERSISTENCE_PATHS = [
    Path.home() / ".config" / "autostart",
    Path.home() / ".local" / "share" / "systemd" / "user",
    Path("/etc/systemd/system"),
    Path("/etc/cron.d"),
    Path("/etc/init.d"),
]


class ProcessCollector:
    """Monitors running processes and detects changes."""

    def __init__(self, state: SystemState):
        self.state = state
        self._prev_pids: set[int] = set()
        self._host_namespaces = self._get_namespaces(1)  # PID 1 is host init

    def _get_cgroups(self, pid: int) -> list[str]:
        """Read /proc/[pid]/cgroup to identify container membership."""
        try:
            path = Path(f"/proc/{pid}/cgroup")
            if not path.exists():
                return []
            return path.read_text().splitlines()
        except (PermissionError, OSError):
            return []

    def _get_namespaces(self, pid: int) -> dict[str, str]:
        """Read /proc/[pid]/ns/ links."""
        namespaces = {}
        try:
            ns_dir = Path(f"/proc/{pid}/ns")
            if not ns_dir.exists():
                return {}
            for ns_file in ns_dir.iterdir():
                try:
                    target = os.readlink(ns_file)
                    namespaces[ns_file.name] = target
                except OSError:
                    continue
        except (PermissionError, OSError):
            pass
        return namespaces

    def collect(self) -> list[SecurityEvent]:
        """Snapshot all processes, diff against previous state, return events."""
        events: list[SecurityEvent] = []
        current_pids: set[int] = set()
        current_procs: dict[int, ProcessInfo] = {}

        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'username',
                                          'create_time', 'exe', 'cwd', 'status',
                                          'cpu_percent', 'memory_info']):
            try:
                info = proc.info
                pid = info['pid']
                current_pids.add(pid)

                cmdline = " ".join(info.get('cmdline') or [])
                mem_mb = (info.get('memory_info').rss / 1024 / 1024) if info.get('memory_info') else 0

                # Collect open files for sensitive access detection
                open_files = []
                try:
                    open_files = [f.path for f in proc.open_files()]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Collect network connections
                connections = []
                try:
                    for conn in proc.net_connections():
                        if conn.status in ('ESTABLISHED', 'LISTEN', 'SYN_SENT'):
                            laddr = conn.laddr
                            raddr = conn.raddr if conn.raddr else ("", 0)
                            connections.append(NetConnection(
                                local_addr=laddr.ip if laddr else "",
                                local_port=laddr.port if laddr else 0,
                                remote_addr=raddr[0] if raddr else "",
                                remote_port=raddr[1] if raddr else 0,
                                status=conn.status,
                                pid=pid,
                                process_name=info['name'] or "",
                            ))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Get children
                children = []
                try:
                    children = [c.pid for c in proc.children()]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Get cgroups and namespaces
                cgroups = self._get_cgroups(pid)
                namespaces = self._get_namespaces(pid)

                pinfo = ProcessInfo(
                    pid=pid,
                    ppid=info.get('ppid', 0),
                    name=info.get('name', '') or '',
                    cmdline=cmdline,
                    username=info.get('username', '') or '',
                    create_time=info.get('create_time', 0) or 0,
                    exe=info.get('exe', '') or '',
                    cwd=info.get('cwd', '') or '',
                    connections=connections,
                    open_files=open_files,
                    children=children,
                    cpu_percent=info.get('cpu_percent', 0) or 0,
                    memory_mb=mem_mb,
                    status=info.get('status', '') or '',
                    cgroup=cgroups,
                    namespaces=namespaces,
                )
                current_procs[pid] = pinfo

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Detect NEW processes
        new_pids = current_pids - self._prev_pids
        for pid in new_pids:
            if pid not in current_procs:
                continue
            proc = current_procs[pid]

            # Skip if we're in learning mode
            if self.state.learning_mode:
                self.state.known_good_processes.add(proc.name)
                continue

            event = self._analyze_new_process(proc, current_procs)
            if event:
                events.append(event)

        # Detect EXITED processes (less critical but useful for context)
        exited_pids = self._prev_pids - current_pids
        for pid in exited_pids:
            if pid in self.state.processes:
                old_proc = self.state.processes[pid]
                if old_proc.name in SHELL_BINARIES and old_proc.age_seconds < 5:
                    # Very short-lived shell — could be command injection
                    events.append(tag_event(SecurityEvent(
                        event_type=EventType.PROCESS_SHELL_SPAWN,
                        threat_level=ThreatLevel.YELLOW,
                        process=old_proc,
                        narrative=f"Short-lived shell '{old_proc.name}' (PID {pid}) "
                                  f"exited after {old_proc.age_seconds:.1f}s — possible injection",
                    ), "T1059.004"))

        # Update state
        self._prev_pids = current_pids
        self.state.processes = current_procs
        return events

    def _analyze_new_process(self, proc: ProcessInfo, all_procs: dict[int, ProcessInfo]) -> SecurityEvent | None:
        """Analyze a newly spawned process for suspicious behavior."""

        # Build parent chain
        parent_chain = self._build_parent_chain(proc.pid, all_procs)
        name_lower = proc.name.lower()

        # --- Container Escape Detection (Phase 5) ---
        is_container = any('docker' in cg or 'kubepods' in cg for cg in proc.cgroup)
        if is_container:
            # Check for namespace violations (container process sharing host namespaces)
            if self._host_namespaces and proc.namespaces:
                shared_ns = []
                for ns_type, ns_id in proc.namespaces.items():
                    if ns_type in ('mnt', 'pid', 'net') and ns_id == self._host_namespaces.get(ns_type):
                        shared_ns.append(ns_type)
                
                if 'mnt' in shared_ns:
                    return tag_event(SecurityEvent(
                        event_type=EventType.CONTAINER_ESCAPE,
                        threat_level=ThreatLevel.RED,
                        process=proc,
                        parent_chain=parent_chain,
                        narrative=f"🚨 CONTAINER ESCAPE: Process '{proc.name}' (PID {proc.pid}) in docker cgroup "
                                  f"is using HOST mount namespace! Access to host filesystem detected.",
                    ), "T1611")
                
                if 'pid' in shared_ns and proc.username == 'root':
                    return tag_event(SecurityEvent(
                        event_type=EventType.CONTAINER_ESCAPE,
                        threat_level=ThreatLevel.ORANGE,
                        process=proc,
                        parent_chain=parent_chain,
                        narrative=f"Privileged Container: Process '{proc.name}' (PID {proc.pid}) "
                                  f"shares HOST PID namespace as root.",
                    ), "T1611")

            # Check for direct shell spawn by container runtime
            parent = all_procs.get(proc.ppid)
            if parent and any(r in parent.name for r in ['dockerd', 'containerd', 'runc']):
                if name_lower in SHELL_BINARIES:
                    return tag_event(SecurityEvent(
                        event_type=EventType.CONTAINER_ESCAPE,
                        threat_level=ThreatLevel.ORANGE,
                        process=proc,
                        parent_chain=parent_chain,
                        narrative=f"Container Runtime '{parent.name}' spawned shell '{proc.name}' directly. "
                                  f"Possible container breakout or unauthorized exec.",
                    ), "T1611")

        # 1. Shell spawned by unexpected parent
        if name_lower in SHELL_BINARIES:
            parent = all_procs.get(proc.ppid)
            parent_name = parent.name.lower() if parent else "unknown"

            # Normal shell parents
            normal_parents = {"sshd", "sshd-session", "login", "gdm", "lightdm", "systemd",
                              "tmux", "screen", "gnome-terminal", "xterm", "alacritty",
                              "kitty", "ghostty", "ptyxis-agent", "ptyxis",
                              "code", "bash", "zsh", "sh", "fish", "su", "sudo", "cron",
                              "systemd-user", "init", "tmux: server",
                              "gnome-session-service", "gnome-session-b",
                              "openclaw-gateway", "node", "npm", "codex", "claude"}

            if parent_name not in normal_parents and not parent_name.startswith("tmux"):
                level = ThreatLevel.YELLOW
                # If the parent is an interpreter with network connections, escalate
                if parent and parent.connections:
                    level = ThreatLevel.ORANGE
                return tag_event(SecurityEvent(
                    event_type=EventType.PROCESS_SHELL_SPAWN,
                    threat_level=level,
                    process=proc,
                    parent_chain=parent_chain,
                    narrative=f"Shell '{proc.name}' spawned by unusual parent '{parent_name}' "
                              f"(PID {proc.ppid}). CMD: {proc.cmdline}",
                ), "T1059.004")

        # 2. Suspicious tools
        if name_lower in SUSPICIOUS_TOOLS:
            # Check if it's making outbound connections to unusual destinations
            level = ThreatLevel.YELLOW
            if proc.connections:
                for conn in proc.connections:
                    if conn.remote_port in SUSPICIOUS_PORTS:
                        level = ThreatLevel.ORANGE
            # Map interpreter binaries specifically if needed, but generic suspicious tools -> T1204 (User Execution)
            # or T1059 (Command and Scripting Interpreter) if interpreted.
            # Assuming generic user execution for now unless shell (handled above).
            return tag_event(SecurityEvent(
                event_type=EventType.PROCESS_NEW,
                threat_level=level,
                process=proc,
                parent_chain=parent_chain,
                narrative=f"Suspicious tool '{proc.name}' launched. CMD: {proc.cmdline}",
            ), "T1204")

        # 3. Process accessing sensitive files
        sensitive_access = [f for f in proc.open_files if any(
            s in f for s in ['.ssh', '.gnupg', 'vault', 'secret', 'token', 'credential',
                             '.env', 'shadow', 'sudoers']
        )]
        # AI tools (claude, codex) are whitelisted for credential reads ONLY when
        # spawned by legitimate parents. If their parent chain is suspicious, still flag.
        AI_TOOL_NAMES = {'claude', 'codex'}
        LEGIT_AI_PARENTS = {'node', 'npm', 'openclaw-gateway', 'bash', 'zsh', 'sh',
                            'fish', 'tmux: server', 'tmux', 'screen', 'systemd',
                            'gnome-terminal', 'ptyxis', 'ptyxis-agent', 'ghostty',
                            'alacritty', 'kitty', 'xterm', 'code'}
        ai_tool_legit = False
        if name_lower in AI_TOOL_NAMES and sensitive_access:
            parent = all_procs.get(proc.ppid)
            if parent and parent.name.lower() in LEGIT_AI_PARENTS:
                ai_tool_legit = True
                log.info(f"AI tool '{proc.name}' credential access OK (parent: {parent.name})")
            else:
                # AI tool with suspicious parent accessing creds = ELEVATED threat
                return tag_event(SecurityEvent(
                    event_type=EventType.CREDENTIAL_ACCESS,
                    threat_level=ThreatLevel.RED,
                    process=proc,
                    parent_chain=parent_chain,
                    narrative=f"🚨 AI TOOL HIJACK: '{proc.name}' (PID {proc.pid}) accessing "
                              f"sensitive files with UNUSUAL parent '{parent.name if parent else 'unknown'}'. "
                              f"Files: {sensitive_access}. Parent chain: {' → '.join(parent_chain)}",
                ), "T1552.001")

        if sensitive_access and proc.name not in {'ssh', 'ssh-agent', 'gpg', 'gpg-agent', 'sshd', 'sudo', 'age'} and not ai_tool_legit:
            return tag_event(SecurityEvent(
                event_type=EventType.CREDENTIAL_ACCESS,
                threat_level=ThreatLevel.ORANGE,
                process=proc,
                parent_chain=parent_chain,
                narrative=f"Process '{proc.name}' (PID {proc.pid}) accessing sensitive files: "
                          f"{sensitive_access}. Parent chain: {' → '.join(parent_chain)}",
            ), "T1552.001")

        # 4. New unknown process (not in known good list)
        if proc.name not in self.state.known_good_processes:
            return tag_event(SecurityEvent(
                event_type=EventType.PROCESS_NEW,
                threat_level=ThreatLevel.GREEN,
                process=proc,
                parent_chain=parent_chain,
                narrative=f"New process '{proc.name}' (PID {proc.pid}). CMD: {proc.cmdline}",
            ), "T1204")

        return None

    def _build_parent_chain(self, pid: int, all_procs: dict[int, ProcessInfo], max_depth: int = 10) -> list[str]:
        """Trace process ancestry."""
        chain = []
        current_pid = pid
        seen = set()
        for _ in range(max_depth):
            if current_pid in seen or current_pid <= 1:
                break
            seen.add(current_pid)
            proc = all_procs.get(current_pid)
            if not proc:
                break
            chain.append(f"{proc.name}({proc.pid})")
            current_pid = proc.ppid
        return list(reversed(chain))


class NetworkCollector:
    """Monitors network connections for suspicious activity."""

    def __init__(self, state: SystemState):
        self.state = state
        self._prev_connections: set[str] = set()
        self._prev_listeners: set[int] = set()

    def collect(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        current_connections: set[str] = set()
        current_listeners: set[int] = set()

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    port = conn.laddr.port if conn.laddr else 0
                    current_listeners.add(port)

                    # New listener?
                    if port not in self._prev_listeners and not self.state.learning_mode:
                        pid = conn.pid or 0
                        proc_name = ""
                        try:
                            if pid:
                                proc_name = psutil.Process(pid).name()
                        except psutil.NoSuchProcess:
                            pass

                        net_conn = NetConnection(
                            local_addr=conn.laddr.ip if conn.laddr else "",
                            local_port=port,
                            remote_addr="",
                            remote_port=0,
                            status="LISTEN",
                            pid=pid,
                            process_name=proc_name,
                        )

                        level = ThreatLevel.YELLOW
                        if port in SUSPICIOUS_PORTS:
                            level = ThreatLevel.ORANGE

                        events.append(tag_event(SecurityEvent(
                            event_type=EventType.NETWORK_NEW_LISTEN,
                            threat_level=level,
                            connection=net_conn,
                            narrative=f"New LISTEN port {port} opened by '{proc_name}' (PID {pid})",
                        ), "T1071"))

                elif conn.status == 'ESTABLISHED' and conn.raddr:
                    conn_key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                    current_connections.add(conn_key)

                    # Check for suspicious outbound
                    if conn.raddr.port in SUSPICIOUS_PORTS and not _is_trusted_lan(conn.raddr.ip):
                        pid = conn.pid or 0
                        proc_name = ""
                        try:
                            if pid:
                                proc_name = psutil.Process(pid).name()
                        except psutil.NoSuchProcess:
                            pass

                        net_conn = NetConnection(
                            local_addr=conn.laddr.ip,
                            local_port=conn.laddr.port,
                            remote_addr=conn.raddr.ip,
                            remote_port=conn.raddr.port,
                            status="ESTABLISHED",
                            pid=pid,
                            process_name=proc_name,
                        )
                        events.append(tag_event(SecurityEvent(
                            event_type=EventType.NETWORK_SUSPICIOUS,
                            threat_level=ThreatLevel.ORANGE,
                            connection=net_conn,
                            narrative=f"Connection to suspicious port {conn.raddr.port} "
                                      f"({conn.raddr.ip}) by '{proc_name}' (PID {pid})",
                        ), "T1071"))

        except (psutil.AccessDenied, OSError) as e:
            log.warning(f"Network collection error: {e}")

        if self.state.learning_mode:
            self.state.known_good_connections.update(current_connections)
            self.state.listen_ports = current_listeners

        self._prev_connections = current_connections
        self._prev_listeners = current_listeners
        return events


class FileIntegrityCollector:
    """Monitors critical files for unauthorized changes."""

    def __init__(self, state: SystemState):
        self.state = state
        self._file_hashes: dict[str, str] = {}
        self._file_perms: dict[str, str] = {}
        self._initialized = False

    def collect(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        current_hashes: dict[str, str] = {}
        current_perms: dict[str, str] = {}

        for path in SENSITIVE_PATHS:
            try:
                if path.is_file():
                    if path.stat().st_size > 10 * 1024 * 1024:
                        log.warning(f"Skipping large file: {path}")
                        continue
                    self._hash_file(path, current_hashes, current_perms)
                elif path.is_dir():
                    self._scan_directory(path, current_hashes, current_perms)
            except (PermissionError, OSError):
                continue

        if not self._initialized:
            # First run — establish baseline
            self._file_hashes = current_hashes
            self._file_perms = current_perms
            self._initialized = True
            self.state.file_hashes = dict(current_hashes)
            log.info(f"File integrity baseline established: {len(current_hashes)} files")
            return events

        # Detect changes
        for filepath, new_hash in current_hashes.items():
            old_hash = self._file_hashes.get(filepath)

            if old_hash is None:
                # New file in sensitive location
                events.append(tag_event(SecurityEvent(
                    event_type=EventType.FILE_CREATED,
                    threat_level=ThreatLevel.YELLOW,
                    file_event=FileEvent(
                        path=filepath,
                        event_type="created",
                        new_hash=new_hash,
                    ),
                    narrative=f"New file created in sensitive location: {filepath}",
                ), "T1005"))

            elif old_hash != new_hash:
                # File modified
                level = ThreatLevel.YELLOW
                # SSH keys or auth files = higher severity
                if any(s in filepath for s in ['authorized_keys', 'id_rsa', 'id_ed25519',
                                                 'shadow', 'sudoers', '.bashrc', '.zshrc']):
                    level = ThreatLevel.ORANGE

                events.append(tag_event(SecurityEvent(
                    event_type=EventType.FILE_MODIFIED,
                    threat_level=level,
                    file_event=FileEvent(
                        path=filepath,
                        event_type="modified",
                        old_hash=old_hash,
                        new_hash=new_hash,
                    ),
                    narrative=f"Sensitive file modified: {filepath}",
                ), "T1005"))

            # Check permission changes
            old_perm = self._file_perms.get(filepath, "")
            new_perm = current_perms.get(filepath, "")
            if old_perm and new_perm and old_perm != new_perm:
                level = ThreatLevel.YELLOW
                # World-writable = bad
                if new_perm.endswith("7") or new_perm == "0o777":
                    level = ThreatLevel.ORANGE
                events.append(tag_event(SecurityEvent(
                    event_type=EventType.FILE_PERMISSION_CHANGE,
                    threat_level=level,
                    file_event=FileEvent(
                        path=filepath,
                        event_type="permission_changed",
                        old_perms=old_perm,
                        new_perms=new_perm,
                    ),
                    narrative=f"File permissions changed: {filepath} ({old_perm} → {new_perm})",
                ), "T1005"))

        # Detect deletions
        for filepath in set(self._file_hashes.keys()) - set(current_hashes.keys()):
            events.append(tag_event(SecurityEvent(
                event_type=EventType.FILE_MODIFIED,
                threat_level=ThreatLevel.ORANGE,
                file_event=FileEvent(path=filepath, event_type="deleted"),
                narrative=f"Sensitive file DELETED: {filepath}",
            ), "T1005"))

        self._file_hashes = current_hashes
        self._file_perms = current_perms
        self.state.file_hashes = dict(current_hashes)
        return events

    def _scan_directory(self, root: Path, current_hashes: dict, current_perms: dict):
        """Recursively scan directory with depth and exclusion limits."""
        root = root.resolve()
        # Initial depth is based on the root path
        root_parts_len = len(root.parts)
        
        # Use os.walk for efficiency
        for dirpath, dirnames, filenames in os.walk(str(root)):
            path = Path(dirpath)
            
            # Check depth relative to root
            current_depth = len(path.parts) - root_parts_len
            if current_depth > 3:
                dirnames.clear() # Don't descend further
                continue
                
            # Filter excluded directories in-place
            for d in list(dirnames):
                if d in EXCLUDED_DIRS:
                    log.info(f"Skipping excluded dir: {path / d}")
                    dirnames.remove(d)
            
            # Process files
            for f in filenames:
                file_path = path / f
                try:
                    if file_path.stat().st_size > 10 * 1024 * 1024:
                        log.warning(f"Skipping large file: {file_path}")
                        continue
                    self._hash_file(file_path, current_hashes, current_perms)
                except (PermissionError, OSError):
                    continue

    def _hash_file(self, path: Path, hashes: dict, perms: dict):
        try:
            h = hashlib.sha256(path.read_bytes()).hexdigest()
            hashes[str(path)] = h
            perms[str(path)] = oct(path.stat().st_mode)
        except (PermissionError, OSError):
            pass


class SelfIntegrityCollector:
    """Monitors Nova EDR's own files for tampering. Priority #1."""

    def __init__(self, state: SystemState, edr_path: Path):
        self.state = state
        self.edr_path = edr_path
        self._file_hashes: dict[str, str] = {}
        self._initialized = False

    def collect(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        current_hashes: dict[str, str] = {}

        for f in self.edr_path.rglob("*.py"):
            try:
                h = hashlib.sha256(f.read_bytes()).hexdigest()
                current_hashes[str(f)] = h
            except (PermissionError, OSError):
                continue

        # Also monitor config
        config_dir = self.edr_path / "config"
        if config_dir.exists():
            for f in config_dir.rglob("*"):
                if f.is_file():
                    try:
                        h = hashlib.sha256(f.read_bytes()).hexdigest()
                        current_hashes[str(f)] = h
                    except (PermissionError, OSError):
                        continue

        if not self._initialized:
            self._file_hashes = current_hashes
            self._initialized = True
            return events

        # Any change to our own files is CRITICAL
        for filepath, new_hash in current_hashes.items():
            old_hash = self._file_hashes.get(filepath)
            if old_hash and old_hash != new_hash:
                events.append(tag_event(SecurityEvent(
                    event_type=EventType.SELF_TAMPER,
                    threat_level=ThreatLevel.RED,
                    file_event=FileEvent(
                        path=filepath,
                        event_type="modified",
                        old_hash=old_hash,
                        new_hash=new_hash,
                    ),
                    narrative=f"🚨 EDR SELF-TAMPER DETECTED: {filepath} was modified!",
                ), "T1562.001"))

        self._file_hashes = current_hashes
        return events


class VaultIntegrityCollector:
    """Monitors access to the encrypted credential vault."""

    VAULT_WHITELIST = {"openclaw", "nova", "age", "python", "python3", "claude", "codex"}  # AI tools need vault for auth

    def __init__(self, state: SystemState):
        self.state = state
        self.vault_path = VAULT_PATH
        # Known vault secrets to hunt for in plaintext (placeholder)
        self.known_secrets: set[str] = set()

    def collect(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        
        # Check running processes for open handles to vault files
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'open_files']):
            try:
                if not proc.info['open_files']:
                    continue
                
                # Check if any open file is in the vault directory
                vault_access = False
                accessed_files = []
                
                for f in proc.info['open_files']:
                    path = Path(f.path)
                    try:
                        if self.vault_path in path.parents or path == self.vault_path:
                            vault_access = True
                            accessed_files.append(str(path))
                    except (ValueError, OSError):
                        continue
                
                if vault_access:
                    proc_name = proc.info['name']
                    # Check whitelist
                    if proc_name not in self.VAULT_WHITELIST:
                        # Alert!
                        pinfo = ProcessInfo(
                            pid=proc.info['pid'],
                            ppid=0, # Simplified
                            name=proc_name,
                            cmdline=" ".join(proc.info['cmdline'] or []),
                            username=proc.info['username'],
                            create_time=0,
                            open_files=accessed_files
                        )
                        
                        events.append(tag_event(SecurityEvent(
                            event_type=EventType.VAULT_ACCESS,
                            threat_level=ThreatLevel.RED,
                            process=pinfo,
                            narrative=f"🚨 UNAUTHORIZED VAULT ACCESS: Process '{proc_name}' (PID {proc.info['pid']}) "
                                      f"accessed vault files: {accessed_files}",
                        ), "T1555"))
                    else:
                        # Log lawful access (audit trail)
                        log.debug(f"Authorized vault access by {proc_name} (PID {proc.info['pid']})")
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return events


class PlaintextHunter:
    """Scans configuration and source files for plaintext credentials."""

    SCAN_EXTENSIONS = {".env", ".json", ".yaml", ".yml", ".xml", ".py", ".js", ".ts", ".go", ".sh"}
    MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

    def __init__(self, state: SystemState):
        self.state = state
        self.sanitizer = Sanitizer(mode=ScanMode.ALERT)
        self.scanned_files: dict[str, float] = {}  # path -> mtime

    def collect(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        
        # Define scan roots - prioritize likely locations
        scan_roots = [
            Path.home() / "clawd",
            Path.home() / ".config",
            Path.home() / "projects"  # Hypothetical
        ]
        
        # Limit scan duration/files per run to avoid CPU spike
        files_scanned = 0
        limit = 50 
        
        for root in scan_roots:
            if not root.exists():
                continue
                
            for path in root.rglob("*"):
                if files_scanned >= limit:
                    break
                
                if path.is_file() and path.suffix in self.SCAN_EXTENSIONS or path.name.startswith(".env"):
                    # Check if file modified since last scan
                    try:
                        mtime = path.stat().st_mtime
                        if path.stat().st_size > self.MAX_FILE_SIZE:
                            continue
                            
                        if str(path) in self.scanned_files and self.scanned_files[str(path)] == mtime:
                            continue
                        
                        # Scan it
                        self.scanned_files[str(path)] = mtime
                        files_scanned += 1
                        
                        try:
                            content = path.read_text(errors='ignore')
                            _, findings = self.sanitizer.sanitize_text(content)
                            
                            if findings:
                                # Report highest severity finding
                                for finding in findings:
                                    events.append(tag_event(SecurityEvent(
                                        event_type=EventType.CREDENTIAL_ACCESS,
                                        threat_level=ThreatLevel.ORANGE,
                                        file_event=FileEvent(
                                            path=str(path),
                                            event_type="plaintext_secret",
                                        ),
                                        narrative=f"PLAINTEXT SECRET FOUND in {path}: {finding.rule_name} "
                                                  f"(Context: ...{finding.context[:50]}...)",
                                    ), "T1552.001"))
                        except (PermissionError, OSError):
                            pass
                            
                    except (PermissionError, OSError):
                        continue
            
            if files_scanned >= limit:
                break
                
        return events
