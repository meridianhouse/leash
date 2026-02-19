"""Adapter primitives for node monitoring across operating systems."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any, Callable

CommandRunner = Callable[[list[str]], str]


@dataclass
class ProcessInfo:
    """Unified process record collected from a monitored node."""

    pid: int
    name: str
    user: str
    cmdline: str
    ppid: int
    cpu_pct: float
    mem_pct: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetConnection:
    """Unified network connection record collected from a monitored node."""

    proto: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseAdapter(ABC):
    """Base interface for OS-specific command collection and parsing."""

    os_type: str

    @abstractmethod
    def process_command(self) -> list[str]:
        """Return command to collect process list output."""

    @abstractmethod
    def network_command(self) -> list[str]:
        """Return command to collect network connection output."""

    @abstractmethod
    def file_hash_command(self) -> list[str]:
        """Return command to collect sensitive file hashes."""

    @abstractmethod
    def parse_processes(self, stdout: str) -> list[ProcessInfo]:
        """Parse raw process command output into unified process objects."""

    @abstractmethod
    def parse_connections(self, stdout: str) -> list[NetConnection]:
        """Parse raw network command output into unified connection objects."""


def build_file_hash_script(extra_sensitive_dirs: list[str] | None = None) -> str:
    """Builds a portable Python script that emits sensitive file hashes as TSV."""

    dirs = [
        ".ssh",
        ".aws",
        ".config/gcloud",
        ".docker",
        ".kube",
    ]
    if extra_sensitive_dirs:
        dirs.extend(extra_sensitive_dirs)

    dir_literals = ", ".join(repr(d) for d in dirs)

    return f"""
import hashlib
import pathlib

home = pathlib.Path.home()

sensitive_dirs = [{dir_literals}]
env_patterns = [".env", ".env.*"]

files = set()

for rel in sensitive_dirs:
    p = home / rel
    if p.is_file():
        files.add(p)
    elif p.is_dir():
        for child in p.rglob("*"):
            if child.is_file():
                files.add(child)

for pattern in env_patterns:
    for p in home.glob(pattern):
        if p.is_file():
            files.add(p)
    for p in home.glob(f"*/{{pattern}}"): 
        if p.is_file():
            files.add(p)
    for p in home.glob(f"*/*/{{pattern}}"): 
        if p.is_file():
            files.add(p)

credential_candidates = [
    home / ".netrc",
    home / ".pypirc",
    home / ".git-credentials",
]
for p in credential_candidates:
    if p.is_file():
        files.add(p)

for path in sorted(files):
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        continue
    print(f"{{path}}\t{{digest}}")
""".strip()
