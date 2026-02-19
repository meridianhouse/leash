"""Node monitoring module for ClawdStrike AI-native EDR."""

from __future__ import annotations

import argparse
import json
import platform
import socket
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nova_edr.adapters import BaseAdapter, CommandRunner, NetConnection, ProcessInfo
from nova_edr.adapters.linux import LinuxAdapter
from nova_edr.adapters.macos import MacOSAdapter
from nova_edr.adapters.windows import WindowsAdapter


@dataclass
class Finding:
    """Security finding generated from baseline diffing."""

    severity: str
    category: str
    description: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NodeInfo:
    """Tracked node metadata for registry persistence."""

    node_id: str
    hostname: str
    os_type: str
    last_seen: str
    health_status: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "NodeInfo":
        return cls(
            node_id=str(value.get("node_id", "")),
            hostname=str(value.get("hostname", "")),
            os_type=str(value.get("os_type", "")),
            last_seen=str(value.get("last_seen", "")),
            health_status=str(value.get("health_status", "unknown")),
        )


@dataclass
class NodeSnapshot:
    """Collected point-in-time node state used for baseline and scans."""

    collected_at: str
    processes: list[ProcessInfo] = field(default_factory=list)
    connections: list[NetConnection] = field(default_factory=list)
    file_hashes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "collected_at": self.collected_at,
            "processes": [p.to_dict() for p in self.processes],
            "connections": [c.to_dict() for c in self.connections],
            "file_hashes": dict(self.file_hashes),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "NodeSnapshot":
        processes = [ProcessInfo(**item) for item in value.get("processes", [])]
        connections = [NetConnection(**item) for item in value.get("connections", [])]
        file_hashes = {
            str(path): str(digest) for path, digest in dict(value.get("file_hashes", {})).items()
        }
        return cls(
            collected_at=str(value.get("collected_at", "")),
            processes=processes,
            connections=connections,
            file_hashes=file_hashes,
        )


def default_command_runner(command: list[str]) -> str:
    """Default command runner implementation using local subprocess execution."""

    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(command)}; {stderr}")
    return proc.stdout


class NodeMonitor:
    """Collects node telemetry, manages baselines, and emits findings."""

    def __init__(self, command_runner: CommandRunner | None = None, storage_dir: str | Path = ".nova_edr"):
        self.command_runner = command_runner or default_command_runner
        self.storage_dir = Path(storage_dir)
        self.registry_path = self.storage_dir / "nodes.json"
        self.baseline_dir = self.storage_dir / "baselines"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        self._adapters: dict[str, BaseAdapter] = {
            "linux": LinuxAdapter(),
            "macos": MacOSAdapter(),
            "windows": WindowsAdapter(),
        }

    def discover(self) -> NodeInfo:
        """Discover and register the local node."""

        hostname = socket.gethostname()
        os_type = self._normalize_os(platform.system())
        node_id = self._build_node_id(hostname, os_type)
        node = NodeInfo(
            node_id=node_id,
            hostname=hostname,
            os_type=os_type,
            last_seen=self._now(),
            health_status="online",
        )
        registry = self.load_registry()
        registry[node.node_id] = node
        self.save_registry(registry)
        return node

    def learn(self, node_id: str) -> NodeSnapshot:
        """Learn baseline for a node by collecting and persisting current state."""

        node = self.get_node(node_id)
        snapshot, collection_findings = self.collect_snapshot(node)
        if collection_findings:
            node.health_status = "degraded"
        else:
            node.health_status = "online"
        node.last_seen = self._now()
        self._upsert_node(node)

        baseline_path = self._baseline_path(node_id)
        baseline_path.write_text(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        return snapshot

    def scan(self, node_id: str) -> list[Finding]:
        """Scan a node against baseline and return findings."""

        node = self.get_node(node_id)
        snapshot, collection_findings = self.collect_snapshot(node)

        baseline = self.load_baseline(node_id)
        findings: list[Finding] = []
        findings.extend(collection_findings)

        if baseline is None:
            findings.append(
                Finding(
                    severity="high",
                    category="baseline",
                    description="Baseline missing for node. Run learn mode before scanning.",
                    evidence={"node_id": node_id},
                )
            )
        else:
            findings.extend(self._diff_processes(baseline, snapshot))
            findings.extend(self._diff_connections(baseline, snapshot))
            findings.extend(self._diff_file_hashes(baseline, snapshot))

        node.last_seen = self._now()
        node.health_status = "degraded" if findings else "online"
        self._upsert_node(node)
        return findings

    def collect_snapshot(self, node: NodeInfo) -> tuple[NodeSnapshot, list[Finding]]:
        """Collect raw telemetry from a node using the OS adapter."""

        adapter = self._adapter_for(node.os_type)
        findings: list[Finding] = []

        proc_stdout = self._run_command(adapter.process_command(), "process_collection", node, findings)
        net_stdout = self._run_command(adapter.network_command(), "network_collection", node, findings)
        file_stdout = self._run_command(adapter.file_hash_command(), "file_hash_collection", node, findings)

        processes = adapter.parse_processes(proc_stdout) if proc_stdout else []
        connections = adapter.parse_connections(net_stdout) if net_stdout else []
        file_hashes = self._parse_file_hashes(file_stdout)

        snapshot = NodeSnapshot(
            collected_at=self._now(),
            processes=processes,
            connections=connections,
            file_hashes=file_hashes,
        )
        return snapshot, findings

    def load_registry(self) -> dict[str, NodeInfo]:
        """Load node registry from disk."""

        if not self.registry_path.exists():
            return {}
        raw = json.loads(self.registry_path.read_text(encoding="utf-8"))
        return {str(k): NodeInfo.from_dict(v) for k, v in dict(raw).items()}

    def save_registry(self, registry: dict[str, NodeInfo]) -> None:
        """Persist node registry to disk."""

        payload = {node_id: node.to_dict() for node_id, node in registry.items()}
        self.registry_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def get_node(self, node_id: str) -> NodeInfo:
        """Retrieve a node from registry."""

        registry = self.load_registry()
        node = registry.get(node_id)
        if not node:
            raise KeyError(f"unknown node_id: {node_id}")
        return node

    def load_baseline(self, node_id: str) -> NodeSnapshot | None:
        """Load baseline state for a node if available."""

        path = self._baseline_path(node_id)
        if not path.exists():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
        return NodeSnapshot.from_dict(raw)

    def _upsert_node(self, node: NodeInfo) -> None:
        registry = self.load_registry()
        registry[node.node_id] = node
        self.save_registry(registry)

    def _baseline_path(self, node_id: str) -> Path:
        if ".." in node_id or "/" in node_id or "\\" in node_id:
             raise ValueError(f"Invalid node_id: {node_id}")
        return self.baseline_dir / f"{node_id}.json"

    def _adapter_for(self, os_type: str) -> BaseAdapter:
        adapter = self._adapters.get(os_type.lower())
        if not adapter:
            raise ValueError(f"unsupported os_type: {os_type}")
        return adapter

    def _run_command(
        self,
        command: list[str],
        category: str,
        node: NodeInfo,
        findings: list[Finding],
    ) -> str:
        try:
            return self.command_runner(command)
        except Exception as exc:  # broad by design for adapter/runner compatibility
            findings.append(
                Finding(
                    severity="medium",
                    category=category,
                    description="Command execution failed during telemetry collection.",
                    evidence={
                        "node_id": node.node_id,
                        "command": command,
                        "error": str(exc),
                    },
                )
            )
            return ""

    def _parse_file_hashes(self, stdout: str) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line or "\t" not in line:
                continue
            path, digest = line.split("\t", 1)
            path = path.strip()
            digest = digest.strip()
            if path and digest:
                hashes[path] = digest
        return hashes

    def _diff_processes(self, baseline: NodeSnapshot, current: NodeSnapshot) -> list[Finding]:
        baseline_set = {self._process_key(p) for p in baseline.processes}
        findings: list[Finding] = []
        for proc in current.processes:
            key = self._process_key(proc)
            if key in baseline_set:
                continue
            findings.append(
                Finding(
                    severity="high",
                    category="process",
                    description="New unknown process observed on node.",
                    evidence={"process": proc.to_dict()},
                )
            )
        return findings

    def _diff_connections(self, baseline: NodeSnapshot, current: NodeSnapshot) -> list[Finding]:
        baseline_set = {self._connection_key(c) for c in baseline.connections}
        findings: list[Finding] = []
        for conn in current.connections:
            key = self._connection_key(conn)
            if key in baseline_set:
                continue
            findings.append(
                Finding(
                    severity="medium",
                    category="network",
                    description="Unexpected network connection observed on node.",
                    evidence={"connection": conn.to_dict()},
                )
            )
        return findings

    def _diff_file_hashes(self, baseline: NodeSnapshot, current: NodeSnapshot) -> list[Finding]:
        findings: list[Finding] = []

        all_paths = set(baseline.file_hashes) | set(current.file_hashes)
        for path in sorted(all_paths):
            previous = baseline.file_hashes.get(path)
            present = current.file_hashes.get(path)

            if previous is None and present is not None:
                findings.append(
                    Finding(
                        severity="medium",
                        category="file_integrity",
                        description="New sensitive file observed.",
                        evidence={"path": path, "old_hash": None, "new_hash": present},
                    )
                )
                continue

            if previous is not None and present is None:
                findings.append(
                    Finding(
                        severity="high",
                        category="file_integrity",
                        description="Sensitive file missing since baseline.",
                        evidence={"path": path, "old_hash": previous, "new_hash": None},
                    )
                )
                continue

            if previous != present:
                findings.append(
                    Finding(
                        severity="high",
                        category="file_integrity",
                        description="Sensitive file hash changed from baseline.",
                        evidence={"path": path, "old_hash": previous, "new_hash": present},
                    )
                )
        return findings

    @staticmethod
    def _process_key(proc: ProcessInfo) -> tuple[str, str, str]:
        return (proc.user, proc.name, proc.cmdline)

    @staticmethod
    def _connection_key(conn: NetConnection) -> tuple[str, str, int, str, int, str]:
        return (
            conn.proto,
            conn.local_addr,
            conn.local_port,
            conn.remote_addr,
            conn.remote_port,
            conn.state,
        )

    @staticmethod
    def _build_node_id(hostname: str, os_type: str) -> str:
        cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in hostname).strip("-")
        return f"{cleaned}-{os_type}"

    @staticmethod
    def _normalize_os(raw: str) -> str:
        value = raw.lower()
        if value.startswith("linux"):
            return "linux"
        if value.startswith("darwin") or value.startswith("mac"):
            return "macos"
        if value.startswith("win"):
            return "windows"
        raise ValueError(f"unsupported local operating system: {raw}")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ClawdStrike node monitor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--discover", action="store_true", help="Discover and register local node")
    group.add_argument("--scan", metavar="NODE_ID", help="Scan node against baseline")
    group.add_argument("--learn", metavar="NODE_ID", help="Learn baseline for node")
    parser.add_argument(
        "--storage-dir",
        default=".nova_edr",
        help="Directory for node registry and baselines",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    monitor = NodeMonitor(storage_dir=args.storage_dir)

    try:
        if args.discover:
            node = monitor.discover()
            _print_json({"action": "discover", "node": node.to_dict()})
            return 0

        if args.learn:
            snapshot = monitor.learn(args.learn)
            _print_json(
                {
                    "action": "learn",
                    "node_id": args.learn,
                    "snapshot": snapshot.to_dict(),
                }
            )
            return 0

        if args.scan:
            findings = monitor.scan(args.scan)
            _print_json(
                {
                    "action": "scan",
                    "node_id": args.scan,
                    "findings": [f.to_dict() for f in findings],
                }
            )
            return 0
    except (KeyError, ValueError, RuntimeError) as exc:
        _print_json({"error": str(exc)})
        return 1

    _print_json({"error": "no action selected"})
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
