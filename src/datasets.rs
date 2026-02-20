use crate::config::DatasetConfig;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RmmToolInfo {
    pub name: String,
    pub description: String,
    pub reference_url: String,
    pub installation_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DriverInfo {
    pub id: String,
    pub category: String,
    pub reference_url: String,
    pub cve: Vec<String>,
    pub sha256_hashes: HashSet<String>,
    pub filenames: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetManager {
    pub rmm_tools: HashMap<String, RmmToolInfo>,
    pub rmm_paths: Vec<(String, String)>,
    pub driver_hashes: HashSet<String>,
    pub driver_names: HashMap<String, DriverInfo>,
    pub last_updated: DateTime<Utc>,
}

impl Default for DatasetManager {
    fn default() -> Self {
        Self {
            rmm_tools: HashMap::new(),
            rmm_paths: Vec::new(),
            driver_hashes: HashSet::new(),
            driver_names: HashMap::new(),
            last_updated: Utc::now(),
        }
    }
}

impl DatasetManager {
    pub fn is_stale(&self) -> bool {
        Utc::now().signed_duration_since(self.last_updated) > Duration::days(7)
    }

    pub fn is_stale_for_days(&self, days: i64) -> bool {
        Utc::now().signed_duration_since(self.last_updated) > Duration::days(days.max(1))
    }

    pub fn check_process_name(&self, name: &str) -> Option<&RmmToolInfo> {
        let normalized = normalize_process_name(name);
        self.rmm_tools.get(&normalized)
    }

    pub fn check_file_hash(&self, sha256: &str) -> Option<&DriverInfo> {
        let normalized = normalize_sha256(sha256);
        self.driver_names
            .values()
            .find(|info| info.sha256_hashes.contains(&normalized))
    }

    pub fn check_driver_name(&self, filename: &str) -> Option<&DriverInfo> {
        let normalized = normalize_filename(filename);
        self.driver_names.get(&normalized)
    }

    pub fn save_cache(&self, cache_dir: &Path) -> Result<()> {
        fs::create_dir_all(cache_dir)
            .with_context(|| format!("failed to create dataset cache dir {}", cache_dir.display()))?;

        let data = serde_json::to_vec(self).context("failed to serialize datasets")?;
        let target = cache_dir.join("datasets.json");
        fs::write(&target, data)
            .with_context(|| format!("failed to write dataset cache {}", target.display()))?;
        Ok(())
    }

    pub fn load_cache(cache_dir: &Path) -> Result<Self> {
        let target = cache_dir.join("datasets.json");
        let bytes = fs::read(&target)
            .with_context(|| format!("failed to read dataset cache {}", target.display()))?;
        serde_json::from_slice(&bytes).context("failed to deserialize dataset cache")
    }

    pub async fn fetch_lolrmm(&mut self, url: &str) -> Result<()> {
        let raw = reqwest::get(url)
            .await
            .with_context(|| format!("failed to fetch LOLRMM dataset from {url}"))?
            .error_for_status()
            .with_context(|| format!("LOLRMM fetch returned an error status from {url}"))?
            .text()
            .await
            .context("failed to read LOLRMM response body")?;

        self.apply_lolrmm_json(&raw)
    }

    pub async fn fetch_loldrivers(&mut self, url: &str) -> Result<()> {
        let raw = reqwest::get(url)
            .await
            .with_context(|| format!("failed to fetch LOLDrivers dataset from {url}"))?
            .error_for_status()
            .with_context(|| format!("LOLDrivers fetch returned an error status from {url}"))?
            .text()
            .await
            .context("failed to read LOLDrivers response body")?;

        self.apply_loldrivers_json(&raw)
    }

    pub async fn refresh_from_config(&mut self, cfg: &DatasetConfig) -> Result<()> {
        self.fetch_lolrmm(&cfg.lolrmm_url).await?;
        self.fetch_loldrivers(&cfg.loldrivers_url).await?;
        self.last_updated = Utc::now();
        Ok(())
    }

    pub fn load_or_default(cache_dir: &Path) -> Self {
        Self::load_cache(cache_dir).unwrap_or_default()
    }

    pub fn rmm_tool_count(&self) -> usize {
        self.rmm_tools.len()
    }

    pub fn driver_hash_count(&self) -> usize {
        self.driver_hashes.len()
    }

    fn apply_lolrmm_json(&mut self, raw: &str) -> Result<()> {
        let tools: Vec<RawRmmTool> = serde_json::from_str(raw).context("failed to parse LOLRMM JSON")?;

        self.rmm_tools.clear();
        self.rmm_paths.clear();

        for tool in tools {
            let tool_name = tool.name.trim().to_string();
            if tool_name.is_empty() {
                continue;
            }

            let reference_url = tool
                .references
                .iter()
                .find(|value| value.starts_with("http://") || value.starts_with("https://"))
                .cloned()
                .unwrap_or_else(|| "https://lolrmm.io/".to_string());

            for path in tool.details.installation_paths.iter().filter(|s| !s.trim().is_empty()) {
                self.rmm_paths.push((path.to_string(), tool_name.clone()));
            }

            let mut process_names = HashSet::new();
            for metadata in tool.details.pe_metadata {
                for candidate in [metadata.filename, metadata.original_file_name, metadata.internal_name] {
                    let normalized = normalize_process_name(&candidate);
                    if !normalized.is_empty() {
                        process_names.insert(normalized);
                    }
                }
            }

            for install_path in &tool.details.installation_paths {
                let normalized = normalize_process_name(install_path);
                if !normalized.is_empty() {
                    process_names.insert(normalized);
                }
            }

            if process_names.is_empty() {
                let fallback = normalize_process_name(&tool_name);
                if !fallback.is_empty() {
                    process_names.insert(fallback);
                }
            }

            for process_name in process_names {
                self.rmm_tools.insert(
                    process_name,
                    RmmToolInfo {
                        name: tool_name.clone(),
                        description: tool.description.clone(),
                        reference_url: reference_url.clone(),
                        installation_paths: tool.details.installation_paths.clone(),
                    },
                );
            }
        }

        Ok(())
    }

    fn apply_loldrivers_json(&mut self, raw: &str) -> Result<()> {
        let drivers: Vec<RawDriverEntry> =
            serde_json::from_str(raw).context("failed to parse LOLDrivers JSON")?;

        self.driver_hashes.clear();
        self.driver_names.clear();

        for entry in drivers {
            let reference_url = entry
                .references
                .iter()
                .find(|value| value.starts_with("http://") || value.starts_with("https://"))
                .cloned()
                .unwrap_or_else(|| "https://www.loldrivers.io/".to_string());

            let mut hashes = HashSet::new();
            let mut filenames = HashSet::new();

            for sample in entry.known_vulnerable_samples {
                if !sample.sha256.trim().is_empty() {
                    let normalized_hash = normalize_sha256(&sample.sha256);
                    if !normalized_hash.is_empty() {
                        self.driver_hashes.insert(normalized_hash.clone());
                        hashes.insert(normalized_hash);
                    }
                }

                if !sample.original_filename.trim().is_empty() {
                    let normalized_name = normalize_filename(&sample.original_filename);
                    if !normalized_name.is_empty() {
                        filenames.insert(normalized_name);
                    }
                }
            }

            for tag in entry.tags {
                let normalized_name = normalize_filename(&tag);
                if !normalized_name.is_empty() {
                    filenames.insert(normalized_name);
                }
            }

            if hashes.is_empty() && filenames.is_empty() {
                continue;
            }

            let info = DriverInfo {
                id: entry.id,
                category: entry.category,
                reference_url,
                cve: entry.cve,
                sha256_hashes: hashes,
                filenames: filenames.clone(),
            };

            for filename in filenames {
                self.driver_names.insert(filename, info.clone());
            }
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct RawRmmTool {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Description", default)]
    description: String,
    #[serde(rename = "References", default)]
    references: Vec<String>,
    #[serde(rename = "Details", default)]
    details: RawRmmDetails,
}

#[derive(Debug, Deserialize, Default)]
struct RawRmmDetails {
    #[serde(rename = "PEMetadata", default)]
    pe_metadata: Vec<RawPeMetadata>,
    #[serde(rename = "InstallationPaths", default)]
    installation_paths: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawPeMetadata {
    #[serde(rename = "Filename", alias = "FileName", default)]
    filename: String,
    #[serde(rename = "OriginalFileName", default)]
    original_file_name: String,
    #[serde(rename = "InternalName", default)]
    internal_name: String,
}

#[derive(Debug, Deserialize, Default)]
struct RawDriverEntry {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "Category", default)]
    category: String,
    #[serde(rename = "CVE", default)]
    cve: Vec<String>,
    #[serde(rename = "Tags", default)]
    tags: Vec<String>,
    #[serde(rename = "References", default)]
    references: Vec<String>,
    #[serde(rename = "KnownVulnerableSamples", default)]
    known_vulnerable_samples: Vec<RawDriverSample>,
}

#[derive(Debug, Deserialize, Default)]
struct RawDriverSample {
    #[serde(rename = "SHA256", default)]
    sha256: String,
    #[serde(rename = "OriginalFilename", default)]
    original_filename: String,
}

fn normalize_process_name(input: &str) -> String {
    let token = input
        .trim()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();

    token
        .strip_suffix(".exe")
        .unwrap_or(token.as_str())
        .to_string()
}

fn normalize_filename(input: &str) -> String {
    input
        .trim()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase()
}

fn normalize_sha256(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

pub fn compute_sha256_hex(bytes: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut data = bytes.to_vec();
    let bit_len = (data.len() as u64) * 8;
    data.push(0x80);
    while (data.len() % 64) != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (index, word) in w.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 =
                w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
            let s1 =
                w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    h.iter().map(|word| format!("{word:08x}")).collect()
}

pub fn default_cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config/leash/datasets")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lolrmm_sample_and_extracts_process_names() {
        let sample = r#"
[
  {
    "Name": "AnyDesk",
    "Description": "Remote desktop",
    "References": ["https://lolrmm.io/"],
    "Details": {
      "PEMetadata": [
        {"Filename": "AnyDesk.exe", "OriginalFileName": "AnyDesk.exe", "InternalName": "AnyDesk"}
      ],
      "InstallationPaths": [
        "C:/Program Files/AnyDesk/AnyDesk.exe"
      ]
    }
  }
]
"#;

        let mut manager = DatasetManager::default();
        manager
            .apply_lolrmm_json(sample)
            .expect("sample lolrmm json should parse");

        let anydesk = manager
            .check_process_name("anydesk")
            .expect("anydesk should be indexed");
        assert_eq!(anydesk.name, "AnyDesk");
        assert_eq!(manager.rmm_tool_count(), 1);
    }

    #[test]
    fn parses_loldrivers_sample_and_extracts_hashes() {
        let sample = r#"
[
  {
    "Id": "driver-1",
    "Category": "Vulnerable driver",
    "KnownVulnerableSamples": [
      {
        "SHA256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "OriginalFilename": "bad.sys"
      }
    ],
    "References": ["https://www.loldrivers.io/"]
  }
]
"#;

        let mut manager = DatasetManager::default();
        manager
            .apply_loldrivers_json(sample)
            .expect("sample loldrivers json should parse");

        assert_eq!(manager.driver_hash_count(), 1);
        assert!(manager
            .check_file_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .is_some());
        assert!(manager.check_driver_name("bad.sys").is_some());
    }

    #[test]
    fn check_process_name_matches_anydesk() {
        let mut manager = DatasetManager::default();
        manager.rmm_tools.insert(
            "anydesk".to_string(),
            RmmToolInfo {
                name: "AnyDesk".to_string(),
                description: "Remote desktop".to_string(),
                reference_url: "https://lolrmm.io/".to_string(),
                installation_paths: vec![],
            },
        );

        assert!(manager.check_process_name("anydesk").is_some());
        assert!(manager.check_process_name("ANyDesk").is_some());
    }

    #[test]
    fn check_file_hash_matches_known_hash() {
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut hashes = HashSet::new();
        hashes.insert(hash.to_string());

        let mut names = HashSet::new();
        names.insert("vuln.sys".to_string());

        let info = DriverInfo {
            id: "id-1".to_string(),
            category: "vulnerable".to_string(),
            reference_url: "https://www.loldrivers.io/".to_string(),
            cve: vec![],
            sha256_hashes: hashes.clone(),
            filenames: names,
        };

        let mut manager = DatasetManager::default();
        manager.driver_hashes.insert(hash.to_string());
        manager.driver_names.insert("vuln.sys".to_string(), info);

        assert!(manager.check_file_hash(hash).is_some());
    }

    #[test]
    fn compute_sha256_hex_matches_known_value() {
        let digest = compute_sha256_hex(b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
