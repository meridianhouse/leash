"""Skill scanner for pre-install supply-chain security checks.

This module performs static and heuristic analysis on skill repositories:
- Python and JavaScript static call analysis for dangerous functions
- Dependency verification and typosquat detection
- URL/domain and curl-pipe-shell analysis
- Prompt-injection and obfuscation indicators
- Semantic review prompt construction (stub, no external API calls)

CLI usage:
    python3 -m nova_edr.scanner_skill ./path/to/skill --verbose
"""

from __future__ import annotations

import argparse
import ast
import json
import math
import re
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


class Severity(str, Enum):
    """Severity levels for scanner findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


@dataclass
class Finding:
    """Single scanner finding."""

    severity: Severity
    category: str
    title: str
    description: str
    file: str | None = None
    line: int | None = None
    evidence: str | None = None
    mitre_technique: str | None = None


@dataclass
class ScanReport:
    """Structured skill scan report."""

    target: str
    signatures_file: str
    findings: list[Finding] = field(default_factory=list)
    semantic_prompt: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def highest_severity(self) -> str:
        if not self.findings:
            return Severity.INFO.value
        highest = max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity
        return highest.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "signatures_file": self.signatures_file,
            "highest_severity": self.highest_severity(),
            "summary": self.summary(),
            "findings": [
                {
                    **asdict(f),
                    "severity": f.severity.value,
                }
                for f in sorted(self.findings, key=lambda x: SEVERITY_ORDER[x.severity], reverse=True)
            ],
            "semantic_analysis_stub": self.semantic_prompt,
        }


class SkillScanner:
    """Main scanner class for skill repository auditing."""

    TEXT_EXTENSIONS = {
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".md",
        ".txt",
        ".json",
        ".yaml",
        ".yml",
        ".html",
        ".sh",
    }

    SOURCE_EXTENSIONS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh"}
    SKIP_DIRS = {
        ".git",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
        "logs",
    }
    SKIP_FILES = {"learned_state.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
    MAX_FILE_BYTES = 2_000_000

    def __init__(self, target_path: Path, signatures_path: Path, verbose: bool = False):
        self.target_path = target_path.resolve()
        self.signatures_path = signatures_path.resolve()
        self.verbose = verbose
        self.signatures = self._load_signatures(self.signatures_path)

    def scan(self) -> ScanReport:
        """Run all scanners and return a consolidated report."""
        report = ScanReport(target=str(self.target_path), signatures_file=str(self.signatures_path))

        if not self.target_path.exists() or not self.target_path.is_dir():
            report.add(
                Finding(
                    severity=Severity.CRITICAL,
                    category="input",
                    title="Invalid target path",
                    description="Target path does not exist or is not a directory.",
                    file=str(self.target_path),
                )
            )
            return report

        files = list(self._iter_files(self.target_path))
        self._scan_static_analysis(files, report)
        self._scan_dependency_verification(report)
        self._scan_urls(files, report)
        self._scan_injection_patterns(files, report)
        self._build_semantic_stub(files, report)

        if not report.findings:
            report.add(
                Finding(
                    severity=Severity.INFO,
                    category="scanner",
                    title="No immediate issues detected",
                    description="No configured signatures or heuristics were triggered.",
                )
            )

        return report

    def _log(self, message: str) -> None:
        if self.verbose:
            print(f"[scanner] {message}", file=sys.stderr)

    @staticmethod
    def _load_signatures(path: Path) -> dict[str, Any]:
        """Load YAML signatures from disk."""
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Unable to read signatures file {path}: {exc}") from exc

        try:
            loaded = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise RuntimeError(f"Invalid YAML in signatures file {path}: {exc}") from exc

        if not isinstance(loaded, dict):
            raise RuntimeError(f"Signatures file {path} must contain a top-level mapping")
        return loaded

    def _iter_files(self, root: Path):
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in self.SKIP_DIRS for part in path.parts):
                continue
            if path.name in self.SKIP_FILES:
                continue
            try:
                if path.stat().st_size > self.MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path

    @staticmethod
    def _safe_read(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _scan_static_analysis(self, files: list[Path], report: ScanReport) -> None:
        self._log("running static analysis")
        for file_path in files:
            suffix = file_path.suffix.lower()
            if suffix == ".py":
                self._scan_python_ast(file_path, report)
            elif suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}:
                self._scan_javascript_calls(file_path, report)

    def _scan_python_ast(self, file_path: Path, report: ScanReport) -> None:
        content = self._safe_read(file_path)
        if not content.strip():
            return

        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError as exc:
            report.add(
                Finding(
                    severity=Severity.LOW,
                    category="static_analysis",
                    title="Python parse failure",
                    description="Could not parse Python file for AST analysis.",
                    file=str(file_path),
                    line=exc.lineno,
                    evidence=str(exc),
                )
            )
            return

        dangerous = set(self.signatures.get("dangerous_functions", {}).get("python", []))
        obfuscated = set(self.signatures.get("dangerous_functions", {}).get("obfuscation", []))

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = self._python_call_name(node.func)
            if not call_name:
                continue

            if call_name in dangerous:
                severity = Severity.HIGH
                if call_name in {"os.system", "subprocess.Popen", "subprocess.run", "exec", "eval"}:
                    severity = Severity.CRITICAL
                report.add(
                    Finding(
                        severity=severity,
                        category="static_analysis",
                        title="Dangerous Python function call",
                        description=f"Detected call to '{call_name}'.",
                        file=str(file_path),
                        line=getattr(node, "lineno", None),
                        evidence=self._line_excerpt(content, getattr(node, "lineno", None)),
                        mitre_technique="T1059.006" # Python
                    )
                )

            if call_name in obfuscated or call_name in {"base64.b64decode", "base64.decodebytes", "codecs.decode"}:
                report.add(
                    Finding(
                        severity=Severity.HIGH,
                        category="static_analysis",
                        title="Potential obfuscation decode routine",
                        description=f"Detected decode call '{call_name}' commonly used in payload decoding.",
                        file=str(file_path),
                        line=getattr(node, "lineno", None),
                        evidence=self._line_excerpt(content, getattr(node, "lineno", None)),
                        mitre_technique="T1027" # Obfuscation
                    )
                )

    def _scan_javascript_calls(self, file_path: Path, report: ScanReport) -> None:
        """Best-effort JS/TS call-expression analysis."""
        content = self._safe_read(file_path)
        if not content.strip():
            return

        dangerous = set(self.signatures.get("dangerous_functions", {}).get("javascript", []))
        js_calls = self._extract_js_calls(content)
        dangerous_hits = {
            "eval": Severity.CRITICAL,
            "Function": Severity.HIGH,
            "child_process.exec": Severity.CRITICAL,
            "child_process.execSync": Severity.CRITICAL,
            "child_process.spawn": Severity.HIGH,
            "child_process.spawnSync": Severity.HIGH,
            "execSync": Severity.CRITICAL,
            "spawnSync": Severity.HIGH,
        }
        for call_name, line in js_calls:
            if call_name in dangerous or call_name in dangerous_hits:
                severity = dangerous_hits.get(call_name, Severity.HIGH)
                report.add(
                    Finding(
                        severity=severity,
                        category="static_analysis",
                        title="Dangerous JavaScript function call",
                        description=f"Detected call to '{call_name}'.",
                        file=str(file_path),
                        line=line,
                        evidence=self._line_excerpt(content, line),
                        mitre_technique="T1059.004" if "spawn" in call_name or "exec" in call_name else "T1059"
                    )
                )

        # Shell-pipe execution pattern is still best handled as text signature.
        for match in re.finditer(r"\bcurl\b[^\n|]*\|\s*(bash|sh)\b", content):
            line = self._line_number(content, match.start())
            report.add(
                Finding(
                    severity=Severity.CRITICAL,
                    category="static_analysis",
                    title="Dangerous shell pipe pattern",
                    description="Detected 'curl|bash' execution pattern.",
                    file=str(file_path),
                    line=line,
                    evidence=self._line_excerpt(content, line),
                    mitre_technique="T1059.004"
                )
            )

    def _scan_dependency_verification(self, report: ScanReport) -> None:
        self._log("running dependency verification")
        dependency_cfg = self.signatures.get("dependencies", {})
        popular_py = set(dependency_cfg.get("popular_python_packages", []))
        popular_npm = set(dependency_cfg.get("popular_npm_packages", []))
        known_bad = set(dependency_cfg.get("known_bad_packages", []))

        req_file = self.target_path / "requirements.txt"
        if req_file.exists():
            for line_no, raw in enumerate(self._safe_read(req_file).splitlines(), start=1):
                pkg = self._extract_python_requirement_name(raw)
                if not pkg:
                    continue
                self._check_dependency_name(
                    package_name=pkg,
                    ecosystem="python",
                    popular=popular_py,
                    known_bad=known_bad,
                    file=req_file,
                    line=line_no,
                    report=report,
                )

        pkg_json = self.target_path / "package.json"
        if pkg_json.exists():
            content = self._safe_read(pkg_json)
            try:
                payload = json.loads(content)
            except json.JSONDecodeError as exc:
                report.add(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="dependency_verification",
                        title="Invalid package.json",
                        description="Could not parse package.json.",
                        file=str(pkg_json),
                        line=exc.lineno,
                        evidence=str(exc),
                    )
                )
                payload = {}

            if isinstance(payload, dict):
                sections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
                for section in sections:
                    deps = payload.get(section, {})
                    if not isinstance(deps, dict):
                        continue
                    for pkg in deps.keys():
                        line = self._locate_json_key_line(content, pkg)
                        self._check_dependency_name(
                            package_name=pkg,
                            ecosystem="npm",
                            popular=popular_npm,
                            known_bad=known_bad,
                            file=pkg_json,
                            line=line,
                            report=report,
                        )

    def _check_dependency_name(
        self,
        package_name: str,
        ecosystem: str,
        popular: set[str],
        known_bad: set[str],
        file: Path,
        line: int | None,
        report: ScanReport,
    ) -> None:
        normalized = package_name.strip().lower()

        if normalized in known_bad:
            report.add(
                Finding(
                    severity=Severity.CRITICAL,
                    category="dependency_verification",
                    title="Known malicious dependency",
                    description=f"Dependency '{package_name}' is in known-bad package signatures.",
                    file=str(file),
                    line=line,
                    evidence=package_name,
                    mitre_technique="T1195.001"
                )
            )
            return

        # Typosquat heuristic: close edit distance to popular package but not exact match.
        nearest, distance = self._nearest_package(normalized, popular)
        if nearest and distance <= 1 and normalized != nearest:
            report.add(
                Finding(
                    severity=Severity.HIGH,
                    category="dependency_verification",
                    title="Possible typosquatting dependency",
                    description=(
                        f"Dependency '{package_name}' is very close to popular {ecosystem} package '{nearest}' "
                        f"(edit distance {distance})."
                    ),
                    file=str(file),
                    line=line,
                    evidence=package_name,
                    mitre_technique="T1195.001"
                )
            )
        elif nearest and distance == 2 and len(normalized) > 6 and normalized != nearest:
            report.add(
                Finding(
                    severity=Severity.MEDIUM,
                    category="dependency_verification",
                    title="Potential typosquatting dependency",
                    description=(
                        f"Dependency '{package_name}' resembles popular {ecosystem} package '{nearest}' "
                        f"(edit distance {distance})."
                    ),
                    file=str(file),
                    line=line,
                    evidence=package_name,
                    mitre_technique="T1195.001"
                )
            )

    def _scan_urls(self, files: list[Path], report: ScanReport) -> None:
        self._log("running URL analysis")
        expected = set(self.signatures.get("url_patterns", {}).get("expected_domains", []))
        suspicious_regexes = self.signatures.get("url_patterns", {}).get("suspicious", [])

        for file_path in files:
            if file_path.suffix.lower() not in self.TEXT_EXTENSIONS:
                continue

            content = self._safe_read(file_path)
            if not content:
                continue

            for match in re.finditer(r"https?://[^\s\)\]\}\"'<>]+", content):
                url = match.group(0)
                domain = (urlparse(url).hostname or "").lower()
                line = self._line_number(content, match.start())

                if domain and not self._domain_allowed(domain, expected):
                    report.add(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="url_analysis",
                            title="Unexpected external URL domain",
                            description=f"URL domain '{domain}' is not in expected allowlist.",
                            file=str(file_path),
                            line=line,
                            evidence=url,
                            mitre_technique="T1567"
                        )
                    )

            for regex in suspicious_regexes:
                for match in re.finditer(regex, content, flags=re.IGNORECASE):
                    line = self._line_number(content, match.start())
                    report.add(
                        Finding(
                            severity=Severity.CRITICAL,
                            category="url_analysis",
                            title="Suspicious URL/command pattern",
                            description="Detected suspicious URL execution pattern (e.g., curl pipe shell).",
                            file=str(file_path),
                            line=line,
                            evidence=self._line_excerpt(content, line),
                            mitre_technique="T1059.004"
                        )
                    )

    def _scan_injection_patterns(self, files: list[Path], report: ScanReport) -> None:
        self._log("running injection pattern analysis")
        inj_cfg = self.signatures.get("injection_signatures", {})
        phrase_patterns = inj_cfg.get("prompt_injection_phrases", [])
        hidden_regexes = inj_cfg.get("hidden_text_patterns", [])
        obfuscated_regexes = inj_cfg.get("obfuscated_payload_patterns", [])
        min_entropy = float(inj_cfg.get("high_entropy", {}).get("threshold", 4.1))
        min_len = int(inj_cfg.get("high_entropy", {}).get("min_length", 40))

        for file_path in files:
            if file_path.suffix.lower() not in self.TEXT_EXTENSIONS:
                continue
            content = self._safe_read(file_path)
            if not content:
                continue
            obfuscated_hits = 0
            entropy_hits = 0

            for phrase in phrase_patterns:
                regex = re.compile(re.escape(phrase), flags=re.IGNORECASE)
                for match in regex.finditer(content):
                    line = self._line_number(content, match.start())
                    report.add(
                        Finding(
                            severity=Severity.HIGH,
                            category="injection_detection",
                            title="Prompt injection phrase",
                            description=f"Detected suspicious instruction phrase '{phrase}'.",
                            file=str(file_path),
                            line=line,
                            evidence=self._line_excerpt(content, line),
                            mitre_technique="T1566"
                        )
                    )

            for regex in hidden_regexes:
                for match in re.finditer(regex, content, flags=re.DOTALL):
                    line = self._line_number(content, match.start())
                    report.add(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="injection_detection",
                            title="Hidden text indicator",
                            description="Detected hidden text marker (HTML comments or zero-width characters).",
                            file=str(file_path),
                            line=line,
                            evidence=self._line_excerpt(content, line),
                            mitre_technique="T1027"
                        )
                    )

            for regex in obfuscated_regexes:
                for match in re.finditer(regex, content, flags=re.IGNORECASE):
                    if obfuscated_hits >= 25:
                        break
                    token = match.group(0)
                    line = self._line_number(content, match.start())
                    sev = Severity.MEDIUM
                    if self._shannon_entropy(token) >= min_entropy:
                        sev = Severity.HIGH
                    report.add(
                        Finding(
                            severity=sev,
                            category="injection_detection",
                            title="Obfuscated payload indicator",
                            description="Detected encoded/obfuscated payload pattern.",
                            file=str(file_path),
                            line=line,
                            evidence=token[:140],
                            mitre_technique="T1027"
                        )
                    )
                    obfuscated_hits += 1

            for token, line in self._extract_candidate_tokens(content):
                if entropy_hits >= 25:
                    break
                if len(token) < min_len:
                    continue
                entropy = self._shannon_entropy(token)
                if entropy >= min_entropy:
                    report.add(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="injection_detection",
                            title="High-entropy string",
                            description=(
                                f"Detected high-entropy token (length={len(token)}, entropy={entropy:.2f}) "
                                "which may indicate encoded payload data."
                            ),
                            file=str(file_path),
                            line=line,
                            evidence=token[:140],
                            mitre_technique="T1027"
                        )
                    )
                    entropy_hits += 1

    def _build_semantic_stub(self, files: list[Path], report: ScanReport) -> None:
        self._log("building semantic analysis stub")
        readme = self.target_path / "README.md"
        readme_claims = self._safe_read(readme) if readme.exists() else ""

        source_chunks: list[str] = []
        max_chars = 12000
        total = 0
        included_files = 0
        truncated = False
        for file_path in files:
            if file_path.suffix.lower() not in self.SOURCE_EXTENSIONS:
                continue
            content = self._safe_read(file_path)
            if not content.strip():
                continue
            rel = file_path.relative_to(self.target_path)
            chunk = f"\n# FILE: {rel}\n{content}\n"
            if total + len(chunk) > max_chars:
                remaining = max_chars - total
                if remaining > 0:
                    source_chunks.append(chunk[:remaining])
                    total += remaining
                truncated = True
                break
            source_chunks.append(chunk)
            total += len(chunk)
            included_files += 1

        report.semantic_prompt = self.prepare_semantic_review_prompt(
            readme_claims=readme_claims,
            source_code="\n".join(source_chunks),
            included_files=included_files,
            source_chars=total,
            source_truncated=truncated,
        )

    @staticmethod
    def prepare_semantic_review_prompt(
        readme_claims: str,
        source_code: str,
        included_files: int = 0,
        source_chars: int = 0,
        source_truncated: bool = False,
    ) -> dict[str, Any]:
        """Create a structured review prompt payload for a later LLM call.

        This is intentionally a stub and does not call any external APIs.
        """
        return {
            "task": "semantic_skill_audit",
            "instructions": [
                "Compare README claims against actual source behavior.",
                "Identify hidden functionality, data exfiltration, command execution, or privilege escalation.",
                "State whether code does ONLY what README claims.",
                "Return concrete evidence with file and line references.",
            ],
            "inputs": {
                "readme_claims": readme_claims[:10000],
                "source_code": source_code,
            },
            "metadata": {
                "included_source_files": included_files,
                "included_source_chars": source_chars,
                "source_truncated": source_truncated,
            },
            "expected_output_schema": {
                "matches_claims": "boolean",
                "risk_summary": "string",
                "hidden_behaviors": [
                    {
                        "description": "string",
                        "file": "string",
                        "line": "integer",
                        "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
                    }
                ],
                "exfiltration_indicators": ["string"],
                "recommended_action": "allow|review|block",
            },
        }

    @staticmethod
    def _python_call_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = SkillScanner._python_call_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        return None

    @staticmethod
    def _extract_python_requirement_name(line: str) -> str | None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None
        stripped = stripped.split("#", 1)[0].strip()
        if not stripped:
            return None
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "["):
            if sep in stripped:
                stripped = stripped.split(sep, 1)[0].strip()
                break
        return stripped if stripped else None

    @staticmethod
    def _domain_allowed(domain: str, expected_domains: set[str]) -> bool:
        if not expected_domains:
            return True
        if domain in expected_domains:
            return True
        return any(domain.endswith(f".{allowed}") for allowed in expected_domains)

    @staticmethod
    def _line_number(text: str, index: int) -> int:
        return text.count("\n", 0, index) + 1

    @staticmethod
    def _line_excerpt(text: str, line: int | None) -> str:
        if not line or line < 1:
            return ""
        lines = text.splitlines()
        if line > len(lines):
            return ""
        return lines[line - 1].strip()[:220]

    @staticmethod
    def _locate_json_key_line(text: str, key: str) -> int | None:
        pattern = re.compile(rf'"{re.escape(key)}"\s*:')
        match = pattern.search(text)
        if not match:
            return None
        return SkillScanner._line_number(text, match.start())

    @staticmethod
    def _nearest_package(name: str, popular: set[str]) -> tuple[str | None, int]:
        if not popular:
            return None, 999
        nearest = None
        distance = 999
        for candidate in popular:
            dist = SkillScanner._levenshtein(name, candidate)
            if dist < distance:
                nearest = candidate
                distance = dist
        return nearest, distance

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)

        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, start=1):
            curr = [i]
            for j, cb in enumerate(b, start=1):
                insert_cost = curr[j - 1] + 1
                delete_cost = prev[j] + 1
                replace_cost = prev[j - 1] + (0 if ca == cb else 1)
                curr.append(min(insert_cost, delete_cost, replace_cost))
            prev = curr
        return prev[-1]

    @staticmethod
    def _extract_candidate_tokens(text: str) -> list[tuple[str, int]]:
        """Extract long compact tokens for entropy analysis."""
        token_re = re.compile(r"[A-Za-z0-9+/=_-]{24,}")
        tokens: list[tuple[str, int]] = []
        for match in token_re.finditer(text):
            token = match.group(0)
            line = SkillScanner._line_number(text, match.start())
            tokens.append((token, line))
        return tokens

    @staticmethod
    def _extract_js_calls(content: str) -> list[tuple[str, int]]:
        """Extract JS/TS call names and line numbers from source text."""
        call_re = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(")
        calls: list[tuple[str, int]] = []
        for match in call_re.finditer(content):
            call_name = match.group(1)
            line = SkillScanner._line_number(content, match.start())
            calls.append((call_name, line))
        return calls

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        freq: dict[str, int] = {}
        for char in value:
            freq[char] = freq.get(char, 0) + 1
        entropy = 0.0
        length = len(value)
        for count in freq.values():
            p = count / length
            entropy += - p * math.log2(p)
        return entropy


def _default_signatures_path() -> Path:
    return Path(__file__).resolve().parent.parent / "config" / "signatures.yaml"


def build_arg_parser() -> argparse.ArgumentParser:
    """Build CLI arg parser for skill scanner."""
    parser = argparse.ArgumentParser(description="Nova EDR Skill Scanner")
    parser.add_argument("target", type=Path, help="Path to skill directory")
    parser.add_argument(
        "--signatures",
        type=Path,
        default=_default_signatures_path(),
        help="Path to signatures.yaml (default: config/signatures.yaml)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose progress logs")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        scanner = SkillScanner(target_path=args.target, signatures_path=args.signatures, verbose=args.verbose)
        report = scanner.scan()
    except RuntimeError as exc:
        print(
            json.dumps(
                {
                    "error": str(exc),
                    "target": str(args.target),
                    "signatures_file": str(args.signatures),
                },
                indent=2,
            )
        )
        return 2

    print(json.dumps(report.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
