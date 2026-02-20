# Security Audit #6 - Leash v0.2

Date: 2026-02-20
Scope: New v0.2 code paths in `src/datasets.rs`, `src/ebpf.rs`, and new detection logic in `src/collector.rs`.
Prior audits reviewed first: `SECURITY_AUDIT_4.md`, `SECURITY_AUDIT_5.md` (note: #5 is truncated in-repo).

## Findings

### 1) Unbounded remote fetch + no request timeout enables remote DoS/OOM
- Severity: **Critical**
- Affected code: `src/datasets.rs:151`, `src/datasets.rs:164`, `src/datasets.rs:216`, `src/datasets.rs:250`, `src/datasets.rs:283`, `src/datasets.rs:310`, `src/datasets.rs:338`, `src/datasets.rs:361`
- Description:
  - Dataset HTTP responses are read with `.text().await` and no explicit body-size cap.
  - Requests use default reqwest timeouts (effectively no total request deadline unless configured elsewhere).
  - A malicious/compromised upstream can return extremely large bodies (or very slow streaming responses), causing memory exhaustion, long hangs, and startup/update failures.
  - GTFOBins/LOT/LOLC2 tree enumeration can also amplify fetch volume by returning a massive tree.
- Recommended fix:
  - Use a hardened shared `reqwest::Client` with strict connect/read/total timeouts.
  - Enforce max response size per endpoint (e.g., via `content_length` checks plus streaming with hard byte caps).
  - Bound number of entries processed per tree and cap per-file body size.
  - Fail closed on over-limit payloads and keep last known good cache.
- Exploitable in practice: **Yes** (remote, low complexity if any upstream endpoint is compromised or attacker can tamper traffic).

### 2) Dataset transport/authentication model allows poisoning and persistent trust corruption
- Severity: **High**
- Affected code: `src/config.rs:301`, `src/config.rs:673`, `src/datasets.rs:177`, `src/datasets.rs:178`, `src/datasets.rs:179`, `src/datasets.rs:180`, `src/datasets.rs:181`, `src/datasets.rs:131`, `src/datasets.rs:143`
- Description:
  - `datasets.lolrmm_url` and `datasets.loldrivers_url` accept both `http://` and `https://` in config validation.
  - All remote datasets are accepted unsigned and unpinned, then persisted to cache and trusted by detection logic.
  - This creates a straightforward poisoning path: adversary-controlled feed can inject noisy/common process names or crafted entries, producing alert floods or suppressing signal quality.
- Recommended fix:
  - Enforce HTTPS-only for all dataset endpoints.
  - Add dataset authenticity controls (signed metadata, pinned commit/tag/digest, or trusted mirror with signature verification).
  - Add sanity validation before accepting new dataset snapshots (entry-count deltas, schema constraints, allowlisted hostnames).
  - Keep previous cache and roll back on suspicious updates.
- Exploitable in practice: **Yes** (MITM if HTTP is configured, or via upstream compromise/supply-chain attack).

### 3) Dataset cache write/read is vulnerable to local tampering, symlink abuse, and TOCTOU races
- Severity: **High**
- Affected code: `src/datasets.rs:132`, `src/datasets.rs:138`, `src/datasets.rs:145`
- Description:
  - Cache directory/file creation uses `create_dir_all` + `fs::write`/`fs::read` with no ownership, type, or symlink checks.
  - No explicit mode hardening (`0700` dir / `0600` file), so security depends on ambient umask and path trust.
  - If cache path is in a writable/shared location, another local user/process can tamper with `datasets.json` and poison detections persistently.
  - There is a TOCTOU window between path resolution and write/read where symlink or file replacement can occur.
- Recommended fix:
  - Create cache directory with restrictive permissions and validate owner.
  - Open cache file using secure flags (`O_NOFOLLOW`, regular-file checks, atomic temp-write + `rename`).
  - Reject non-owned/non-regular files on load.
  - Consider embedding a local integrity tag (signed metadata or HMAC keyed locally).
- Exploitable in practice: **Conditional Yes** (depends on cache path permissions; high impact where path is shared or misconfigured).

### 4) URL credentials can leak into logs during dataset fetch failures
- Severity: **Medium**
- Affected code: `src/datasets.rs:153`, `src/datasets.rs:155`, `src/datasets.rs:166`, `src/datasets.rs:168`
- Description:
  - Error contexts include full dataset URL values. If operators place tokens in URLs (query/basic auth), failures may log secrets.
- Recommended fix:
  - Sanitize/redact URLs before logging (strip userinfo/query fragments).
  - Prefer token headers from secure config storage rather than URL parameters.
- Exploitable in practice: **Yes** (information disclosure if sensitive URLs are used and logs are accessible).

### 5) YAML/JSON parser resource controls are missing for untrusted dataset content
- Severity: **Medium**
- Affected code: `src/datasets.rs:230`, `src/datasets.rs:301`, `src/datasets.rs:352`, `src/datasets.rs:743`, `src/datasets.rs:795`, `src/datasets.rs:798`, `src/datasets.rs:836`, `src/datasets.rs:839`
- Description:
  - Untrusted remote JSON/YAML is parsed without explicit structural/depth/alias limits.
  - Even without memory-unsafe deserialization, parser CPU/memory exhaustion remains possible with maliciously complex payloads.
- Recommended fix:
  - Enforce strict input size limits before parsing.
  - Add parse budget limits where possible (depth/alias controls), and reject oversize/overcomplex documents.
  - Pre-filter tree entries and cap parsed records.
- Exploitable in practice: **Yes** (DoS via malicious upstream content).

### 6) eBPF object trust boundary is weak (env override + no file trust validation)
- Severity: **High**
- Affected code: `src/ebpf.rs:68`, `src/ebpf.rs:190`, `src/ebpf.rs:248`, `src/ebpf.rs:249`
- Description:
  - `LEASH_EBPF_OBJECT` can override the object path.
  - Loader only checks existence; it does not validate ownership, permissions, digest, or signature.
  - In privileged deployments, loading an attacker-chosen `.o` can alter monitoring behavior or abuse kernel attack surface (verifier bugs are historically real).
- Recommended fix:
  - Remove runtime env override in production mode, or gate behind explicit secure debug flag.
  - Require trusted owner/mode checks and cryptographic verification of eBPF object.
  - Prefer shipping embedded object bytes in signed release artifacts.
- Exploitable in practice: **Conditional Yes** (requires ability to influence object path/file; impact is high in privileged runtime).

### 7) Unsafe eBPF event decoding performs potentially unaligned struct read (UB risk)
- Severity: **Medium**
- Affected code: `src/ebpf.rs:652`
- Description:
  - `let raw = unsafe { *(buf.as_ptr() as *const RawEbpfEvent) };` dereferences a raw pointer as `RawEbpfEvent`.
  - This assumes alignment guarantees that are not explicit at this boundary; unaligned reads are undefined behavior in Rust.
  - Crafted or unexpected buffer layout can lead to crashes or miscompilation-driven behavior.
- Recommended fix:
  - Replace with `ptr::read_unaligned` into a POD type, or decode fields with explicit byte parsing.
  - Add fuzz tests specifically for malformed/truncated perf-event buffers.
- Exploitable in practice: **Potentially** (depends on runtime alignment behavior; still a correctness/security bug in unsafe code).

### 8) Detection bypass is feasible via simple command-shape mutations
- Severity: **High**
- Affected code: `src/collector.rs:975`, `src/collector.rs:980`, `src/collector.rs:981`, `src/collector.rs:982`, `src/collector.rs:983`, `src/collector.rs:1040`
- Description:
  - Many detections rely on exact substring layouts (e.g., `"| bash"`, `"| sh"`, `"curl "`, `"chmod +x"`).
  - Adversarial agents can evade with minor lexical changes (`|bash`, `$IFS`, shell indirection, variable expansion, command substitution, alternative interpreters).
  - For a monitoring tool defending against adaptive AI agents, this is a practical evasion path.
- Recommended fix:
  - Move from string-substring heuristics to shell-aware tokenization/AST parsing for common interpreters.
  - Normalize whitespace/operator variants aggressively and add adversarial mutation tests.
  - Add behavior-based correlation (download + execution graph) instead of single-line literals.
- Exploitable in practice: **Yes** (easy for an attacker intentionally trying to evade).

### 9) Some new detectors are highly noise-prone and can cause alert fatigue
- Severity: **Medium**
- Affected code: `src/collector.rs:1156`, `src/collector.rs:1172`, `src/collector.rs:1176`
- Description:
  - `ai_skill_directory_spawn` triggers on broad working-directory substrings.
  - `ld_preload_set` triggers on any `LD_PRELOAD` presence.
  - Broad detections can generate persistent false positives, reducing analyst trust and masking true positives.
- Recommended fix:
  - Add context gates (parent lineage, executable class, repetition thresholds, known-good allow rules).
  - Track detector precision metrics and tune severity/rate-limiting per rule.
  - Add confidence scoring instead of binary triggering for noisy heuristics.
- Exploitable in practice: **Yes** (operational exploitation via alert flooding / signal dilution).

## Additional Notes Requested in Scope

- ReDoS risk in new matcher logic:
  - No regex engine is used in `src/collector.rs` dangerous-command matcher path; classic regex backtracking ReDoS is **not present** in this code path.
- Netlink buffer-overflow risk:
  - No direct classical overflow found in proc-connector parsing due explicit length checks.
  - Main parser risk observed is unsafe decoding boundary in eBPF event parsing (Finding #7), not netlink slice overrun.
- Path traversal:
  - No direct remote path traversal identified in new dataset fetch logic; main filesystem risk is cache path trust/symlink handling (Finding #3).
- Covert channel potential:
  - Dataset auto-update can be repurposed as a periodic outbound beacon if dataset URLs are attacker-controlled (low-bandwidth channel).

## Priority Fix Order
1. Fix remote DoS/OOM controls for dataset fetch/parse (Finding #1).
2. Lock dataset trust model (HTTPS-only + authenticity verification) (Finding #2).
3. Harden cache file creation/load semantics and permissions (Finding #3).
4. Harden eBPF object trust and unsafe decode path (Findings #6 and #7).
5. Improve detection robustness against evasive command mutations and noisy rules (Findings #8 and #9).
