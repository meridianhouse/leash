"""macOS command adapter for node monitoring."""

from __future__ import annotations

import os
import re
import shlex
from typing import Final

from . import BaseAdapter, NetConnection, ProcessInfo, build_file_hash_script

_LSOF_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(TCP|UDP)\b\s+(\S+?)(?:->(\S+))?(?:\s+\(([^)]+)\))?$"
)


class MacOSAdapter(BaseAdapter):
    """macOS parser and command set."""

    os_type = "macos"

    def process_command(self) -> list[str]:
        return ["ps", "-axo", "user,pid,ppid,pcpu,pmem,command"]

    def network_command(self) -> list[str]:
        return ["lsof", "-nP", "-i"]

    def file_hash_command(self) -> list[str]:
        return ["python3", "-c", build_file_hash_script()]

    def parse_processes(self, stdout: str) -> list[ProcessInfo]:
        results: list[ProcessInfo] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("user"):
                continue
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            user, pid, ppid, cpu, mem, cmdline = parts
            try:
                parsed_pid = int(pid)
                parsed_ppid = int(ppid)
                cpu_pct = float(cpu)
                mem_pct = float(mem)
            except ValueError:
                continue

            results.append(
                ProcessInfo(
                    pid=parsed_pid,
                    name=self._extract_name(cmdline),
                    user=user,
                    cmdline=cmdline,
                    ppid=parsed_ppid,
                    cpu_pct=cpu_pct,
                    mem_pct=mem_pct,
                )
            )
        return results

    def parse_connections(self, stdout: str) -> list[NetConnection]:
        results: list[NetConnection] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("COMMAND"):
                continue

            parts = line.split()
            if len(parts) < 9:
                continue
            try:
                pid = int(parts[1])
            except ValueError:
                continue

            match = _LSOF_RE.search(line)
            if not match:
                continue

            proto = match.group(1).lower()
            local = match.group(2)
            remote = match.group(3) or "*:*"
            state = (match.group(4) or "UNKNOWN").upper()

            local_addr, local_port = self._split_endpoint(local)
            remote_addr, remote_port = self._split_endpoint(remote)

            results.append(
                NetConnection(
                    proto=proto,
                    local_addr=local_addr,
                    local_port=local_port,
                    remote_addr=remote_addr,
                    remote_port=remote_port,
                    state=state,
                    pid=pid,
                )
            )
        return results

    @staticmethod
    def _extract_name(cmdline: str) -> str:
        try:
            token = shlex.split(cmdline)[0]
        except (ValueError, IndexError):
            token = cmdline.split()[0] if cmdline.split() else cmdline
        return os.path.basename(token) or token

    @staticmethod
    def _split_endpoint(value: str) -> tuple[str, int]:
        value = value.strip()
        if value in {"*", "*:*", "-"}:
            return "*", 0
        if value.startswith("[") and "]:" in value:
            host, port = value.rsplit("]:", 1)
            return host.lstrip("["), MacOSAdapter._safe_port(port)
        if ":" not in value:
            return value, 0
        host, port = value.rsplit(":", 1)
        return host, MacOSAdapter._safe_port(port)

    @staticmethod
    def _safe_port(value: str) -> int:
        if not value.isdigit():
            return 0
        return int(value)
