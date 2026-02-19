"""Windows command adapter for node monitoring."""

from __future__ import annotations

import csv
import io
import os
import re
import shlex

from . import BaseAdapter, NetConnection, ProcessInfo, build_file_hash_script


class WindowsAdapter(BaseAdapter):
    """Windows parser and command set."""

    os_type = "windows"

    def process_command(self) -> list[str]:
        return [
            "wmic",
            "process",
            "get",
            "Name,ProcessId,ParentProcessId,CommandLine",
            "/FORMAT:CSV",
        ]

    def network_command(self) -> list[str]:
        return ["netstat", "-ano"]

    def file_hash_command(self) -> list[str]:
        return ["python", "-c", build_file_hash_script(extra_sensitive_dirs=["AppData/Roaming/Microsoft/Credentials"])]

    def parse_processes(self, stdout: str) -> list[ProcessInfo]:
        results: list[ProcessInfo] = []
        reader = csv.DictReader(io.StringIO(stdout))
        for row in reader:
            if not row:
                continue
            pid_raw = (row.get("ProcessId") or "").strip()
            if not pid_raw.isdigit():
                continue
            ppid_raw = (row.get("ParentProcessId") or "").strip()
            ppid = int(ppid_raw) if ppid_raw.isdigit() else -1
            cmdline = (row.get("CommandLine") or "").strip()
            name = (row.get("Name") or "").strip()
            if not name:
                name = self._extract_name(cmdline)

            results.append(
                ProcessInfo(
                    pid=int(pid_raw),
                    name=name,
                    user="unknown",
                    cmdline=cmdline,
                    ppid=ppid,
                    cpu_pct=0.0,
                    mem_pct=0.0,
                )
            )
        return results

    def parse_connections(self, stdout: str) -> list[NetConnection]:
        results: list[NetConnection] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("proto"):
                continue
            if not (line.startswith("TCP") or line.startswith("UDP")):
                continue

            parts = re.split(r"\s+", line)
            if len(parts) < 4:
                continue

            proto = parts[0].lower()
            local = parts[1]
            remote = parts[2]

            if proto == "tcp":
                if len(parts) < 5:
                    continue
                state = parts[3].upper()
                pid_raw = parts[4]
            else:
                state = "NONE"
                pid_raw = parts[3]

            local_addr, local_port = self._split_endpoint(local)
            remote_addr, remote_port = self._split_endpoint(remote)
            pid = int(pid_raw) if pid_raw.isdigit() else -1

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
        if value in {"*", "*:*", "[::]:0", "0.0.0.0:0"}:
            return "*", 0
        if value.startswith("[") and "]:" in value:
            host, port = value.rsplit("]:", 1)
            return host.lstrip("["), WindowsAdapter._safe_port(port)
        if ":" not in value:
            return value, 0
        host, port = value.rsplit(":", 1)
        return host, WindowsAdapter._safe_port(port)

    @staticmethod
    def _safe_port(value: str) -> int:
        if not value.isdigit():
            return 0
        return int(value)
