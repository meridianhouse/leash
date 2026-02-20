# LOLRMM + LOLDrivers Integration Research for Leash v0.2
**Date:** 2026-02-20
**Status:** Research complete, ready for implementation

---

## LOLRMM.io Dataset Analysis

### Overview
- **Total tools cataloged:** 293 RMM tools
- **All categorized as:** RMM (292) + 1 unknown
- **License:** Apache-2.0
- **GitHub:** magicsword-io/LOLRMM — 301 stars, 64 forks
- **Last updated:** 2026-02-13 (actively maintained, ~weekly updates)
- **API endpoint:** `https://lolrmm.io/api/rmm_tools.json` (684KB)

### Data Schema (per tool)
| Field | Description | Useful for Leash? |
|-------|-------------|-------------------|
| `Name` | Tool name (e.g., "AnyDesk") | ✅ Display/alerting |
| `Category` | Always "RMM" | ✅ Classification |
| `Description` | Tool description | ✅ Alert context |
| `Details.PEMetadata` | Filename, OriginalFileName, InternalName, Description, Product | ✅ Process name matching |
| `Details.InstallationPaths` | Known install locations | ✅ FIM + path matching |
| `Details.SupportedOS` | Windows, macOS, Linux | ✅ Filter by OS |
| `Artifacts.Disk` | Log files, config paths | ✅ FIM monitoring |
| `Artifacts.EventLog` | Windows event log entries | ❌ Not relevant for Linux |
| `Artifacts.Registry` | Registry keys | ❌ Not relevant for Linux |
| `Detections` | Links to Sigma rules | ✅ Reference for detection logic |
| `References` | Threat intel links | ✅ Alert enrichment |

### Notable Tools in Dataset
Key RMM tools that threat actors abuse (and that an AI agent might download):
- AnyDesk (3 install paths, 1 PE entry)
- TeamViewer (4 install paths, 1 PE entry)
- ScreenConnect / ConnectWise (14 install paths — most paths of any tool)
- SimpleHelp (5-7 install paths)
- RustDesk (5 install paths) — open-source, easy to deploy silently
- Splashtop (3-7 install paths)
- GoToAssist (2-19 install paths)
- LogMeIn (6 install paths)
- MeshCentral — open-source, commonly abused
- Tactical RMM — open-source, popular with threat actors

### AI Agent Relevance
An AI agent could realistically:
1. `curl` or `wget` an RMM tool binary
2. `chmod +x` and execute it
3. Establish a reverse connection to an attacker's relay
4. All without triggering traditional malware detection (these are legitimate signed tools)

Leash already detects `rmm_suspicious_parent` (T1219) for known RMM names spawned by IDE parents. The LOLRMM dataset expands this from ~5 hardcoded names to 293 tools with process names, install paths, and file artifacts.

---

## LOLDrivers.io Dataset Analysis

### Overview
- **Total drivers cataloged:** 509
- **Categories:** Vulnerable driver (385), Malicious (110), Vulnerable (13), Malicious driver (1)
- **Total known samples:** 1,927 (with 1,925 having SHA256 hashes)
- **Verified entries:** 432 TRUE, 76 FALSE
- **Primary MITRE technique:** T1068 (Exploitation for Privilege Escalation) — 490 entries
- **License:** Apache-2.0
- **GitHub:** magicsword-io/LOLDrivers — 1,404 stars, 176 forks
- **Last updated:** 2026-02-12 (actively maintained)
- **API endpoint:** `https://www.loldrivers.io/api/drivers.json` (27.8MB — large!)
- **Dataset size concern:** 28MB is too large to cache in full. Need to extract just hashes + metadata.

### Data Schema (per driver)
| Field | Description | Useful for Leash? |
|-------|-------------|-------------------|
| `Id` | UUID | ✅ Dedup/tracking |
| `Tags` | Driver filename(s) | ✅ FIM filename matching |
| `Category` | vulnerable driver / malicious | ✅ Severity classification |
| `MitreID` | ATT&CK technique | ✅ Already mapped |
| `CVE` | Associated CVEs | ✅ Alert enrichment |
| `Commands.Usecase` | "Elevate privileges", etc. | ✅ Alert context |
| `KnownVulnerableSamples[].SHA256` | File hash | ✅ FIM hash matching |
| `KnownVulnerableSamples[].Authentihash.SHA256` | Authenticode hash | ✅ Secondary verification |
| `KnownVulnerableSamples[].OriginalFilename` | Driver filename | ✅ Filename matching |
| `Detection` | Sigma/YARA rules | ✅ Reference |

### BYOVD Attack Landscape (2025-2026)
Real-world attacks are accelerating:
- **Osiris Ransomware (Nov 2025):** POORTRY driver used for BYOVD to disarm security
- **EnCase Driver Abuse (Feb 2026):** Revoked Guidance Software driver used to terminate 59 security tools
- **Black Basta:** Embeds vulnerable driver directly in ransomware payload
- **CrowdStrike incident (Sep 2024):** Adversaries brought 6 vulnerable drivers to bypass Falcon
- Research found 917 known vulnerable drivers, 48 additional suspicious, 7 confirmed weaponized

### AI Agent Relevance
BYOVD via AI agent is a realistic attack vector:
1. Agent downloads a known vulnerable signed driver
2. Loads it via `insmod`/`modprobe` (Linux) or service creation (Windows)
3. Exploits the driver to gain kernel access
4. Disables Leash itself or other security tools
5. All using a legitimately signed binary that passes basic checks

This is particularly concerning because AI agents have the technical knowledge to select the right driver for the target OS/kernel and craft the exploitation steps.

---

## Competitive Landscape

### Who Integrates These Datasets?
| Tool | LOLRMM | LOLDrivers | Notes |
|------|--------|------------|-------|
| MagicSword (Application Control) | ✅ | ✅ | Prevention-focused, blocks at execution |
| Microsoft Defender (KQL) | ❌ | ✅ | Hunt queries, not built-in |
| Splunk | ❌ | ✅ | Lookup tables for hunting |
| Sysmon | ✅ (custom config) | ❌ | Community config files |
| Falco | ❌ | ❌ | Could extend via custom rules |
| Wazuh/OSSEC | ❌ | ❌ | Could extend via custom decoders |
| osquery | ❌ | ❌ | Could query via SQL joins |
| **Leash** | **Planned** | **Planned** | **Would be first AI-agent-focused tool with both** |

### AI Agent Security Tools
- **Levo.ai:** eBPF-based, monitors hallucinations/unsafe tool usage/privilege aggregation. Commercial. Does NOT integrate LOL* datasets.
- **Galileo:** Real-time safety checks, evaluators. Commercial. Prompt/output focused, not OS-level.
- **Helicone:** Proxy-based request logging. Lightweight. No OS-level monitoring.

**Gap:** No open-source AI agent security tool currently integrates either LOLRMM or LOLDrivers. Leash would be the first.

---

## Implementation Plan for Leash v0.2

### New Module: `src/datasets.rs`

```rust
// Dataset management for LOLRMM and LOLDrivers
pub struct DatasetManager {
    rmm_tools: HashMap<String, RmmTool>,      // process name → tool info
    rmm_paths: Vec<(PathBuf, String)>,         // install path → tool name
    driver_hashes: HashMap<String, DriverInfo>, // SHA256 → driver info
    driver_names: HashMap<String, DriverInfo>,  // filename → driver info
    last_updated: DateTime<Utc>,
}
```

### Data Flow
```
leash init
  ├── Fetch lolrmm.io/api/rmm_tools.json (684KB)
  ├── Fetch loldrivers.io/api/drivers.json (28MB)
  ├── Extract & compress to ~/.config/leash/datasets/
  │   ├── rmm_tools.bin (process names, paths, metadata)
  │   └── driver_hashes.bin (SHA256 set + metadata)
  └── Store last_updated timestamp

leash watch / leash start
  ├── Load datasets from cache
  ├── ProcessCollector: cross-ref new process names against rmm_tools
  ├── FIM: cross-ref new/modified file hashes against driver_hashes
  └── Emit SecurityEvent with enriched context (tool name, category, refs)

leash update (new command)
  └── Re-fetch datasets if stale (>7 days)
```

### New Detection Rules
| Detection | MITRE | Severity | Trigger |
|-----------|-------|----------|---------|
| `lolrmm_tool_execution` | T1219 | Red | Process name/path matches LOLRMM entry |
| `lolrmm_artifact_created` | T1219 | Orange | FIM detects file at known LOLRMM artifact path |
| `lolrmm_download` | T1219+T1105 | Red | AI agent downloads file matching RMM tool name |
| `loldriver_hash_match` | T1068 | Red | FIM hash matches LOLDrivers SHA256 |
| `loldriver_filename_match` | T1068 | Orange | File created matching known vulnerable driver name |
| `loldriver_load_attempt` | T1068 | Red | `insmod`/`modprobe` with driver matching dataset |

### Config Additions
```yaml
# Dataset configuration
datasets:
  enabled: true
  cache_dir: "~/.config/leash/datasets"
  auto_update: true
  update_interval_days: 7
  lolrmm:
    enabled: true
    url: "https://lolrmm.io/api/rmm_tools.json"
  loldrivers:
    enabled: true  
    url: "https://www.loldrivers.io/api/drivers.json"
```

### Cargo Dependencies (New)
- None required — can use existing `reqwest` for HTTP, `serde_json` for parsing
- Consider `bincode` for compact cached dataset storage
- The 28MB LOLDrivers JSON should be parsed once and stored as a hash set (~150KB of SHA256 strings)

### Size Impact
- LOLRMM processed cache: ~50KB (293 tools, names + paths)
- LOLDrivers processed cache: ~200KB (1,925 hashes + metadata)
- New Rust code estimate: ~400-600 lines
- Binary size impact: minimal (~50KB)

### Testing Plan
1. Unit tests: dataset parsing, hash matching, process name matching
2. Integration test: mock process with RMM tool name → verify detection fires
3. Integration test: create file with known LOLDrivers hash → verify FIM detection
4. Offline test: verify graceful degradation when datasets unavailable
5. Update test: verify stale cache triggers refresh

---

## Advisor Analysis

### Security Architect Perspective
**Strong addition.** The LOLRMM integration directly extends the existing `rmm_suspicious_parent` detection from 5 hardcoded tools to 293. The LOLDrivers hash matching gives Leash BYOVD detection capability that no other AI agent security tool has. However:
- The 28MB LOLDrivers download is a concern for `leash init` on slow connections. Consider a stripped-down dataset (hashes only, ~200KB).
- Driver loading on Linux requires root — detection should flag the *attempt* (insmod command), not just the loaded driver.
- False positive risk is low for hash matching but moderate for RMM process name matching (legitimate sysadmin use). The allow_list system already handles this.

### Product Strategist Perspective
**Differentiation play.** "First AI agent security tool with LOLRMM + LOLDrivers integration" is a real claim nobody else can make. For the launch narrative:
- Show HN angle: "We added BYOVD detection to our AI agent monitor" — security people will appreciate this
- The r/netsec crowd knows LOLDrivers already. Integrating it signals Leash is built by security people, not just AI people.
- Keep it opt-in (datasets.enabled: true by default, but graceful without internet).

### Pragmatist Perspective
**Scope it tight for v0.2.** The full implementation plan above is ~500 lines of Rust. Ship these in order:
1. Dataset fetch + cache on `leash init` / `leash update` (new command)
2. LOLRMM process name matching in ProcessCollector (highest value, lowest effort)
3. LOLDrivers hash matching in FIM (high value, moderate effort)
4. LOLRMM artifact path monitoring (nice-to-have, lower priority)

Don't try to do Sigma rule parsing or complex behavioral correlation. Simple name/hash matching covers 90% of the value.
