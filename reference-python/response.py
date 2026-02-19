"""Response Engine — graduated containment and alerting.

Response levels:
  GREEN  → Log only
  YELLOW → Alert + forensic snapshot
  ORANGE → Kill process + alert
  RED    → Contain + credential check + alert
  NUCLEAR → Kill all network interfaces
"""

from __future__ import annotations
import json
import logging
import os
import subprocess
import time
from pathlib import Path

import yaml

from .models import SecurityEvent, ThreatLevel, ProcessInfo
from .context import BehaviorSequence

log = logging.getLogger("nova.response")

ALERT_LOG = Path(__file__).parent.parent / "logs" / "alerts.jsonl"
FORENSIC_DIR = Path(__file__).parent.parent / "logs" / "forensics"
DISABLED_FILE = Path(__file__).parent.parent / "config" / "DISABLED"


class ResponseEngine:
    """Executes graduated responses to security events."""

    def __init__(self, alert_callback=None, nuclear_enabled: bool = False):
        """
        alert_callback: async function(message: str) for external alerting (Telegram, etc.)
        nuclear_enabled: whether the nuclear option (kill network) is armed
        """
        self.alert_callback = alert_callback
        self.nuclear_enabled = nuclear_enabled
        self._alert_cooldown: dict[str, float] = {}
        FORENSIC_DIR.mkdir(parents=True, exist_ok=True)
        
        # Initialize protected processes from defaults, then load config
        self.protected_processes = set(self.PROTECTED_PROCESSES)
        self._load_config()

    def _load_config(self):
        """Load protected processes from config."""
        config_path = Path(__file__).parent.parent / "config" / "edr_config.yaml"
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    config = yaml.safe_load(f) or {}
                    if "protected_processes" in config:
                        self.protected_processes.update(config["protected_processes"])
            except Exception as e:
                log.error(f"Failed to load config: {e}")

    def respond_to_event(self, event: SecurityEvent) -> str:
        """Handle a single security event based on threat level."""
        action = "logged"

        if event.threat_level == ThreatLevel.GREEN:
            action = self._handle_green(event)
        elif event.threat_level == ThreatLevel.YELLOW:
            action = self._handle_yellow(event)
        elif event.threat_level == ThreatLevel.ORANGE:
            action = self._handle_orange(event)
        elif event.threat_level == ThreatLevel.RED:
            action = self._handle_red(event)
        elif event.threat_level == ThreatLevel.NUCLEAR:
            action = self._handle_nuclear(event)

        event.response_taken = action
        self._log_alert(event)
        return action

    def respond_to_sequence(self, sequence: BehaviorSequence) -> str:
        """Handle a detected behavioral pattern."""
        log.critical(f"Responding to pattern: {sequence.pattern_name} "
                     f"(threat: {sequence.threat_level.value})")

        # Behavioral patterns get elevated response
        if sequence.threat_level in (ThreatLevel.RED, ThreatLevel.NUCLEAR):
            self._capture_forensics(f"pattern_{sequence.pattern_name}")
            
            mitre_info = ""
            if sequence.mitre_technique:
                mitre_info = f"\nMITRE: {sequence.mitre_technique} - {sequence.mitre_name} ({sequence.mitre_tactic})"
            
            self._alert(f"🚨 BEHAVIORAL PATTERN: {sequence.pattern_name}{mitre_info}\n"
                        f"{sequence.description}\n"
                        f"Threat: {sequence.threat_level.value.upper()}\n"
                        f"Events: {len(sequence.events)}")

            # FREEZE all involved processes (don't kill — let human/AI review)
            frozen = set()
            for event in sequence.events:
                if event.process and event.process.pid not in frozen:
                    if self._freeze_process(event.process):
                        frozen.add(event.process.pid)

            if sequence.threat_level == ThreatLevel.NUCLEAR and self.nuclear_enabled:
                self._nuclear_option()
                return "NUCLEAR — network killed"

            return f"🧊 contained — {len(frozen)} processes frozen (awaiting review)"

        elif sequence.threat_level == ThreatLevel.ORANGE:
            self._capture_forensics(f"pattern_{sequence.pattern_name}")
            
            mitre_info = ""
            if sequence.mitre_technique:
                mitre_info = f"\nMITRE: {sequence.mitre_technique}"

            self._alert(f"⚠️ Suspicious pattern: {sequence.pattern_name}{mitre_info}\n"
                        f"{sequence.description}")
            return "alerted + forensics captured"

        return "logged"

    # --- Threat level handlers ---

    def _handle_green(self, event: SecurityEvent) -> str:
        """Green: log only."""
        return "logged"

    def _handle_yellow(self, event: SecurityEvent) -> str:
        """Yellow: log only (no external alert). Forensic snapshot for review."""
        prefix = f"[{event.mitre_technique}] " if event.mitre_technique else ""
        log.warning(f"🟡 SUSPICIOUS: {prefix}{event.narrative}")
        self._capture_forensics(f"yellow_{int(event.timestamp)}")
        return "logged + forensics"

    def _handle_orange(self, event: SecurityEvent) -> str:
        """Orange: FREEZE process (don't kill) + alert. Let human/AI decide."""
        prefix = f"[{event.mitre_technique}] " if event.mitre_technique else ""
        self._alert(f"🟠 LIKELY MALICIOUS: {prefix}{event.narrative}")
        self._capture_forensics(f"orange_{int(event.timestamp)}")

        if event.process:
            frozen = self._freeze_process(event.process)
            if frozen:
                return f"🧊 FROZEN PID {event.process.pid} + alerted (awaiting review)"
            return f"alerted (couldn't freeze — protected process)"

        return "alerted + forensics"

    def _handle_red(self, event: SecurityEvent) -> str:
        """Red: FREEZE first, then alert. Kill only on confirmed + reviewed."""
        prefix = f"[{event.mitre_technique}] " if event.mitre_technique else ""
        self._alert(f"🔴 CONFIRMED THREAT: {prefix}{event.narrative}\n"
                    f"Process FROZEN for review. Kill pending human/AI approval.")
        self._capture_forensics(f"red_{int(event.timestamp)}")

        if event.process:
            self._freeze_process(event.process)
            # Freeze children too
            self._freeze_process_tree(event.process.pid)

        return f"🧊 frozen + contained + alerted"

    def _handle_nuclear(self, event: SecurityEvent) -> str:
        """Nuclear: kill ALL network interfaces."""
        prefix = f"[{event.mitre_technique}] " if event.mitre_technique else ""
        self._alert(f"☢️ NUCLEAR TRIGGERED: {prefix}{event.narrative}\n"
                    f"KILLING ALL NETWORK INTERFACES")
        self._capture_forensics(f"nuclear_{int(event.timestamp)}")

        if self.nuclear_enabled:
            self._nuclear_option()
            return "NUCLEAR — all network killed"
        else:
            log.critical("NUCLEAR option triggered but NOT ARMED. "
                         "Set nuclear_enabled=True to arm.")
            return "NUCLEAR triggered but not armed"

    # --- Actions ---

    # Processes that must NEVER be stopped/killed (would brick the machine)
    PROTECTED_PROCESSES = {
        "openclaw-gateway", "node", "npm",  # OpenClaw (Nova)
        "claude", "codex",                   # AI coding tools (Claude Code, Codex CLI)
        "sshd", "sshd-session",              # SSH access
        "systemd", "init", "systemd-logind",  # System core
        "gdm", "gnome-session", "gnome-shell", "Xwayland",  # Desktop
        "NetworkManager", "systemd-resolved",  # Networking
    }

    def _is_protected(self, name: str, cmdline: list[str] | str) -> bool:
        """Check if a process is protected from termination."""
        if name in self.protected_processes:
            return True
        
        # Protect specific python processes by cmdline
        if name.startswith("python"):
            cmd = cmdline if isinstance(cmdline, str) else " ".join(cmdline)
            if "nova-edr" in cmd or "run.py" in cmd:
                return True
            if "openclaw" in cmd:
                return True
        return False

    def _is_disabled(self) -> bool:
        """Check if EDR killswitch is active."""
        if DISABLED_FILE.exists():
            log.warning("EDR disabled via killswitch. Action suppressed.")
            return True
        return False

    def _freeze_process(self, proc: ProcessInfo) -> bool:
        """SIGSTOP a process — freezes it instantly without killing.
        The process can be resumed with SIGCONT. Much safer than killing.
        """
        if self._is_disabled():
            return False
            
        try:
            import psutil
            p = psutil.Process(proc.pid)
            
            # Race Condition Check: Verify PID hasn't been reused
            try:
                current_name = p.name()
                current_cmdline = p.cmdline()
                
                if current_name != proc.name:
                    log.warning(f"PID {proc.pid} recycled: expected '{proc.name}' but found '{current_name}'. Skipping freeze.")
                    return False
                
                # Re-check protection with CURRENT process info
                if self._is_protected(current_name, current_cmdline):
                    log.warning(f"REFUSED to freeze protected process '{current_name}' (PID {proc.pid})")
                    return False
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False

            p.suspend()  # Sends SIGSTOP
            log.warning(f"🧊 FROZEN PID {proc.pid} ({proc.name}) — use SIGCONT to resume")
            return True
        except Exception as e:
            log.error(f"Failed to freeze PID {proc.pid}: {e}")
            return False

    def _kill_process(self, proc: ProcessInfo):
        """Kill a specific process. Only used for confirmed threats after freezing."""
        if self._is_disabled():
            return

        try:
            import psutil
            p = psutil.Process(proc.pid)
            
            # Race Condition Check: Verify PID hasn't been reused
            try:
                current_name = p.name()
                current_cmdline = p.cmdline()
                
                if current_name != proc.name:
                    log.warning(f"PID {proc.pid} recycled: expected '{proc.name}' but found '{current_name}'. Skipping kill.")
                    return
                
                # Re-check protection with CURRENT process info
                if self._is_protected(current_name, current_cmdline):
                    log.warning(f"REFUSED to kill protected process '{current_name}' (PID {proc.pid})")
                    return
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return

            p.terminate()
            log.warning(f"Terminated PID {proc.pid} ({proc.name})")
            # Give it 3 seconds, then force kill
            try:
                p.wait(timeout=3)
            except psutil.TimeoutExpired:
                p.kill()
                log.warning(f"Force-killed PID {proc.pid}")
        except Exception as e:
            log.error(f"Failed to kill PID {proc.pid}: {e}")

    def _freeze_process_tree(self, pid: int):
        """Freeze a process and all its children."""
        if self._is_disabled():
            return
            
        try:
            import psutil
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    if not self._is_protected(child.name(), child.cmdline()):
                        child.suspend()
                        log.warning(f"🧊 Frozen child PID {child.pid} ({child.name()})")
                except psutil.NoSuchProcess:
                    pass
        except Exception as e:
            log.error(f"Failed to freeze process tree for PID {pid}: {e}")

    def _kill_process_tree(self, pid: int):
        """Kill a process and all its children. Only after freeze + review."""
        if self._is_disabled():
            return
            
        try:
            import psutil
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    if not self._is_protected(child.name(), child.cmdline()):
                        child.terminate()
                        log.warning(f"Terminated child PID {child.pid} ({child.name()})")
                except psutil.NoSuchProcess:
                    pass
        except Exception as e:
            log.error(f"Failed to kill process tree for PID {pid}: {e}")

    def _nuclear_option(self):
        """Kill ALL network interfaces. Last resort."""
        if self._is_disabled():
            return
            
        log.critical("☢️ EXECUTING NUCLEAR OPTION — killing all network interfaces")
        try:
            # Get all interfaces
            import psutil
            interfaces = psutil.net_if_addrs().keys()
            for iface in interfaces:
                if iface == 'lo':
                    continue  # Keep loopback
                subprocess.run(
                    ['sudo', 'ip', 'link', 'set', iface, 'down'],
                    capture_output=True, timeout=5,
                )
                log.critical(f"Interface {iface} DOWN")
        except Exception as e:
            log.critical(f"Nuclear option failed: {e}")
            # Fallback: try the brute force approach
            try:
                subprocess.run(['sudo', 'nmcli', 'networking', 'off'],
                               capture_output=True, timeout=5)
            except Exception:
                pass

    def _capture_forensics(self, label: str):
        """Capture a forensic snapshot of the system state."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        forensic_file = FORENSIC_DIR / f"{timestamp}_{label}.json"
        try:
            import psutil

            data = {
                "timestamp": timestamp,
                "label": label,
                "processes": [],
                "connections": [],
                "listen_ports": [],
            }

            # Process snapshot
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'username', 'create_time']):
                try:
                    info = proc.info
                    data["processes"].append({
                        "pid": info['pid'],
                        "ppid": info['ppid'],
                        "name": info['name'],
                        "cmdline": " ".join(info.get('cmdline') or []),
                        "username": info['username'],
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Network snapshot
            for conn in psutil.net_connections(kind='inet'):
                try:
                    entry = {
                        "status": conn.status,
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "pid": conn.pid,
                    }
                    data["connections"].append(entry)
                except Exception:
                    continue

            forensic_file.write_text(json.dumps(data, indent=2))
            log.info(f"Forensics captured: {forensic_file}")

        except Exception as e:
            log.error(f"Forensic capture failed: {e}")

    def _alert(self, message: str):
        """Send alert (with cooldown to prevent spam)."""
        # Simple cooldown: same message prefix within 60s is suppressed
        key = message[:50]
        now = time.time()
        if key in self._alert_cooldown and now - self._alert_cooldown[key] < 60:
            return
        self._alert_cooldown[key] = now

        log.critical(f"ALERT: {message}")

        if self.alert_callback:
            try:
                self.alert_callback(message)
            except Exception as e:
                log.error(f"Alert callback failed: {e}")

    def _log_alert(self, event: SecurityEvent):
        """Append event to JSONL alert log."""
        try:
            ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "type": event.event_type.value,
                "threat_level": event.threat_level.value,
                "narrative": event.narrative,
                "response": event.response_taken,
                "mitre": {
                    "technique": event.mitre_technique,
                    "tactic": event.mitre_tactic,
                    "name": event.mitre_name,
                } if event.mitre_technique else None,
            }
            if event.process:
                entry["process"] = {
                    "pid": event.process.pid,
                    "name": event.process.name,
                    "cmdline": event.process.cmdline,
                }
            with open(ALERT_LOG, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            log.error(f"Failed to log alert: {e}")
