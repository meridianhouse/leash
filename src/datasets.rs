use crate::config::DatasetConfig;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const GTFOBINS_TREE_URL: &str =
    "https://api.github.com/repos/GTFOBins/GTFOBins.github.io/git/trees/master?recursive=1";
const GTFOBINS_RAW_BASE_URL: &str =
    "https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master";
const LOT_TUNNELS_TREE_URL: &str =
    "https://api.github.com/repos/lottunnels/lottunnels.github.io/git/trees/main?recursive=1";
const LOT_TUNNELS_RAW_BASE_URL: &str =
    "https://raw.githubusercontent.com/lottunnels/lottunnels.github.io/main";
const LOLC2_TREE_URL: &str =
    "https://api.github.com/repos/lolc2/lolc2.github.io/git/trees/main?recursive=1";
const LOLC2_RAW_BASE_URL: &str = "https://raw.githubusercontent.com/lolc2/lolc2.github.io/main";

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GtfobinInfo {
    pub name: String,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunnelToolInfo {
    pub name: String,
    pub description: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct C2ToolInfo {
    pub name: String,
    pub description: String,
    pub abused_services: Vec<String>,
    pub reference_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetManager {
    pub rmm_tools: HashMap<String, RmmToolInfo>,
    pub rmm_paths: Vec<(String, String)>,
    pub driver_hashes: HashSet<String>,
    pub driver_names: HashMap<String, DriverInfo>,
    #[serde(default)]
    pub gtfobins: HashMap<String, GtfobinInfo>,
    #[serde(default)]
    pub tunnels: HashMap<String, TunnelToolInfo>,
    #[serde(default)]
    pub c2_tools: HashMap<String, C2ToolInfo>,
    pub last_updated: DateTime<Utc>,
}

impl Default for DatasetManager {
    fn default() -> Self {
        Self {
            rmm_tools: HashMap::new(),
            rmm_paths: Vec::new(),
            driver_hashes: HashSet::new(),
            driver_names: HashMap::new(),
            gtfobins: HashMap::new(),
            tunnels: HashMap::new(),
            c2_tools: HashMap::new(),
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

    pub fn check_gtfobin(&self, name: &str) -> Option<&GtfobinInfo> {
        let normalized = normalize_process_name(name);
        self.gtfobins.get(&normalized)
    }

    pub fn check_tunnel_tool(&self, name: &str) -> Option<&TunnelToolInfo> {
        let normalized = normalize_process_name(name);
        self.tunnels.get(&normalized)
    }

    pub fn check_c2_tool(&self, name: &str) -> Option<&C2ToolInfo> {
        let normalized = normalize_process_name(name);
        self.c2_tools.get(&normalized)
    }

    pub fn save_cache(&self, cache_dir: &Path) -> Result<()> {
        fs::create_dir_all(cache_dir).with_context(|| {
            format!("failed to create dataset cache dir {}", cache_dir.display())
        })?;

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
        self.fetch_gtfobins().await?;
        self.fetch_lot_tunnels().await?;
        self.fetch_lolc2().await?;
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

    pub fn gtfobin_count(&self) -> usize {
        self.gtfobins.len()
    }

    pub fn tunnel_tool_count(&self) -> usize {
        self.tunnels.len()
    }

    pub fn c2_tool_count(&self) -> usize {
        self.c2_tools.len()
    }

    pub async fn fetch_gtfobins(&mut self) -> Result<()> {
        let client = reqwest::Client::builder()
            .user_agent("leash-datasets/0.1")
            .build()
            .context("failed to build HTTP client for GTFOBins fetch")?;

        let tree_raw = client
            .get(GTFOBINS_TREE_URL)
            .send()
            .await
            .with_context(|| format!("failed to fetch GTFOBins tree from {GTFOBINS_TREE_URL}"))?
            .error_for_status()
            .with_context(|| {
                format!("GTFOBins tree fetch returned an error status from {GTFOBINS_TREE_URL}")
            })?
            .text()
            .await
            .context("failed to read GTFOBins tree response body")?;

        let tree: RawGithubTree =
            serde_json::from_str(&tree_raw).context("failed to parse GTFOBins tree JSON")?;
        let mut index = HashMap::new();

        for entry in tree.tree {
            if entry.kind != "blob" || !is_gtfobin_markdown_path(&entry.path) {
                continue;
            }

            let Some(stem) = Path::new(&entry.path)
                .file_stem()
                .and_then(|name| name.to_str())
            else {
                continue;
            };
            let normalized = normalize_process_name(stem);
            if normalized.is_empty() {
                continue;
            }

            let raw_url = format!("{GTFOBINS_RAW_BASE_URL}/{}", entry.path);
            let markdown = client
                .get(&raw_url)
                .send()
                .await
                .with_context(|| format!("failed to fetch GTFOBins markdown from {raw_url}"))?
                .error_for_status()
                .with_context(|| {
                    format!("GTFOBins markdown fetch returned an error status from {raw_url}")
                })?
                .text()
                .await
                .with_context(|| format!("failed to read GTFOBins markdown body from {raw_url}"))?;

            let functions = parse_gtfobin_functions(&markdown).unwrap_or_default();
            index.insert(
                normalized.clone(),
                GtfobinInfo {
                    name: normalized,
                    functions,
                },
            );
        }

        self.gtfobins = index;
        Ok(())
    }

    pub async fn fetch_lot_tunnels(&mut self) -> Result<()> {
        let client = reqwest::Client::builder()
            .user_agent("leash-datasets/0.1")
            .build()
            .context("failed to build HTTP client for LOT Tunnels fetch")?;

        let tree_raw = client
            .get(LOT_TUNNELS_TREE_URL)
            .send()
            .await
            .with_context(|| {
                format!("failed to fetch LOT Tunnels tree from {LOT_TUNNELS_TREE_URL}")
            })?
            .error_for_status()
            .with_context(|| {
                format!(
                    "LOT Tunnels tree fetch returned an error status from {LOT_TUNNELS_TREE_URL}"
                )
            })?
            .text()
            .await
            .context("failed to read LOT Tunnels tree response body")?;

        let tree: RawGithubTree =
            serde_json::from_str(&tree_raw).context("failed to parse LOT Tunnels tree JSON")?;
        let mut index = HashMap::new();

        for entry in tree.tree {
            if entry.kind != "blob" || !is_lot_tunnel_data_path(&entry.path) {
                continue;
            }

            let raw_url = format!("{LOT_TUNNELS_RAW_BASE_URL}/{}", entry.path);
            let content = client
                .get(&raw_url)
                .send()
                .await
                .with_context(|| format!("failed to fetch LOT Tunnels entry from {raw_url}"))?
                .error_for_status()
                .with_context(|| {
                    format!("LOT Tunnels entry fetch returned an error status from {raw_url}")
                })?
                .text()
                .await
                .with_context(|| format!("failed to read LOT Tunnels entry body from {raw_url}"))?;

            for (key, info) in parse_lot_tunnel_entries(&entry.path, &content)? {
                index.insert(key, info);
            }
        }

        self.tunnels = index;
        Ok(())
    }

    pub async fn fetch_lolc2(&mut self) -> Result<()> {
        let client = reqwest::Client::builder()
            .user_agent("leash-datasets/0.1")
            .build()
            .context("failed to build HTTP client for LOLC2 fetch")?;

        let tree_raw = client
            .get(LOLC2_TREE_URL)
            .send()
            .await
            .with_context(|| format!("failed to fetch LOLC2 tree from {LOLC2_TREE_URL}"))?
            .error_for_status()
            .with_context(|| {
                format!("LOLC2 tree fetch returned an error status from {LOLC2_TREE_URL}")
            })?
            .text()
            .await
            .context("failed to read LOLC2 tree response body")?;

        let tree: RawGithubTree =
            serde_json::from_str(&tree_raw).context("failed to parse LOLC2 tree JSON")?;
        let mut index = HashMap::new();

        for entry in tree.tree {
            if entry.kind != "blob" || !is_lolc2_data_path(&entry.path) {
                continue;
            }

            let raw_url = format!("{LOLC2_RAW_BASE_URL}/{}", entry.path);
            let content = client
                .get(&raw_url)
                .send()
                .await
                .with_context(|| format!("failed to fetch LOLC2 entry from {raw_url}"))?
                .error_for_status()
                .with_context(|| {
                    format!("LOLC2 entry fetch returned an error status from {raw_url}")
                })?
                .text()
                .await
                .with_context(|| format!("failed to read LOLC2 entry body from {raw_url}"))?;

            for (key, info) in parse_lolc2_entries(&entry.path, &content)? {
                index.insert(key, info);
            }
        }

        self.c2_tools = index;
        Ok(())
    }

    fn apply_lolrmm_json(&mut self, raw: &str) -> Result<()> {
        let tools: Vec<RawRmmTool> =
            serde_json::from_str(raw).context("failed to parse LOLRMM JSON")?;

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

            for path in tool
                .details
                .installation_paths
                .iter()
                .filter(|s| !s.trim().is_empty())
            {
                self.rmm_paths.push((path.to_string(), tool_name.clone()));
            }

            let mut process_names = HashSet::new();
            for metadata in tool.details.pe_metadata {
                for candidate in [
                    metadata.filename,
                    metadata.original_file_name,
                    metadata.internal_name,
                ] {
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
    #[serde(rename = "PEMetadata", default, deserialize_with = "deserialize_pe_metadata")]
    pe_metadata: Vec<RawPeMetadata>,
    #[serde(rename = "InstallationPaths", default, deserialize_with = "deserialize_nullable_strings")]
    installation_paths: Vec<String>,
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Array(arr) => {
            Ok(arr.into_iter().filter_map(|v| v.as_str().map(String::from)).collect())
        }
        serde_json::Value::String(s) => Ok(vec![s]),
        serde_json::Value::Null => Ok(Vec::new()),
        _ => Ok(Vec::new()),
    }
}

fn deserialize_nullable_strings<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Vec<String>>::deserialize(deserializer)?;
    Ok(value.unwrap_or_default())
}

fn deserialize_pe_metadata<'de, D>(deserializer: D) -> std::result::Result<Vec<RawPeMetadata>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Array(arr) => {
            let mut result = Vec::new();
            for item in arr {
                if let Ok(pe) = serde_json::from_value::<RawPeMetadata>(item) {
                    result.push(pe);
                }
            }
            Ok(result)
        }
        serde_json::Value::Object(_) => {
            match serde_json::from_value::<RawPeMetadata>(value) {
                Ok(pe) => Ok(vec![pe]),
                Err(_) => Ok(Vec::new()),
            }
        }
        serde_json::Value::Null => Ok(Vec::new()),
        _ => Err(de::Error::custom("expected array, object, or null for PEMetadata")),
    }
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
    #[serde(rename = "CVE", default, deserialize_with = "deserialize_string_or_vec")]
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

#[derive(Debug, Deserialize, Default)]
struct RawGithubTree {
    #[serde(default)]
    tree: Vec<RawGithubTreeEntry>,
}

#[derive(Debug, Deserialize, Default)]
struct RawGithubTreeEntry {
    #[serde(default)]
    path: String,
    #[serde(rename = "type", default)]
    kind: String,
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

fn is_gtfobin_markdown_path(path: &str) -> bool {
    let path = Path::new(path);
    if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
        return false;
    }

    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .map(|segment| segment == "_gtfobins")
            .unwrap_or(false)
    })
}

fn is_lot_tunnel_data_path(path: &str) -> bool {
    let parsed = Path::new(path);
    let Some(extension) = parsed.extension().and_then(|ext| ext.to_str()) else {
        return false;
    };
    if !matches!(extension, "md" | "yml" | "yaml") {
        return false;
    }

    parsed.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .map(|segment| {
                segment.eq_ignore_ascii_case("_tunnels")
                    || segment.eq_ignore_ascii_case("tunnels")
                    || segment.eq_ignore_ascii_case("_data")
                    || segment.eq_ignore_ascii_case("data")
            })
            .unwrap_or(false)
    })
}

fn is_lolc2_data_path(path: &str) -> bool {
    let parsed = Path::new(path);
    let Some(extension) = parsed.extension().and_then(|ext| ext.to_str()) else {
        return false;
    };
    if !matches!(extension, "md" | "yml" | "yaml") {
        return false;
    }

    let lower_path = path.to_ascii_lowercase();
    if !lower_path.contains("c2") && !lower_path.contains("framework") {
        return false;
    }

    parsed.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .map(|segment| {
                segment.eq_ignore_ascii_case("_c2")
                    || segment.eq_ignore_ascii_case("c2")
                    || segment.eq_ignore_ascii_case("_frameworks")
                    || segment.eq_ignore_ascii_case("frameworks")
                    || segment.eq_ignore_ascii_case("_data")
                    || segment.eq_ignore_ascii_case("data")
                    || segment.eq_ignore_ascii_case("_posts")
                    || segment.eq_ignore_ascii_case("posts")
            })
            .unwrap_or(false)
    })
}

fn parse_gtfobin_functions(markdown: &str) -> Result<Vec<String>> {
    let Some(front_matter) = extract_yaml_front_matter(markdown) else {
        return Ok(Vec::new());
    };
    let parsed: serde_yaml::Value = serde_yaml::from_str(&front_matter)
        .context("failed to parse GTFOBins front matter YAML")?;
    let Some(functions_map) = parsed
        .get("functions")
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return Ok(Vec::new());
    };

    let mut functions = Vec::new();
    for key in functions_map.keys() {
        if let Some(raw) = key.as_str() {
            let normalized = raw.trim().to_ascii_lowercase();
            if !normalized.is_empty() {
                functions.push(normalized);
            }
        }
    }
    functions.sort();
    functions.dedup();

    Ok(functions)
}

fn extract_yaml_front_matter(markdown: &str) -> Option<String> {
    let mut lines = markdown.lines();
    if lines.next()?.trim() != "---" {
        return None;
    }

    let mut yaml = String::new();
    for line in lines {
        if line.trim() == "---" {
            return Some(yaml);
        }
        yaml.push_str(line);
        yaml.push('\n');
    }

    None
}

fn parse_lot_tunnel_entries(path: &str, content: &str) -> Result<Vec<(String, TunnelToolInfo)>> {
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();

    let value = if extension == "md" {
        let Some(front_matter) = extract_yaml_front_matter(content) else {
            return Ok(Vec::new());
        };
        serde_yaml::from_str::<serde_yaml::Value>(&front_matter)
            .with_context(|| format!("failed to parse YAML front matter for LOT Tunnels: {path}"))?
    } else {
        serde_yaml::from_str::<serde_yaml::Value>(content)
            .with_context(|| format!("failed to parse YAML for LOT Tunnels: {path}"))?
    };

    let mut entries = Vec::new();
    match value {
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                if let Some((keys, info)) = build_lot_tunnel_info(path, &item) {
                    for key in keys {
                        entries.push((key, info.clone()));
                    }
                }
            }
        }
        serde_yaml::Value::Mapping(_) => {
            if let Some((keys, info)) = build_lot_tunnel_info(path, &value) {
                for key in keys {
                    entries.push((key, info.clone()));
                }
            }
        }
        _ => {}
    }

    Ok(entries)
}

fn parse_lolc2_entries(path: &str, content: &str) -> Result<Vec<(String, C2ToolInfo)>> {
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();

    let value = if extension == "md" {
        let Some(front_matter) = extract_yaml_front_matter(content) else {
            return Ok(Vec::new());
        };
        serde_yaml::from_str::<serde_yaml::Value>(&front_matter)
            .with_context(|| format!("failed to parse YAML front matter for LOLC2: {path}"))?
    } else {
        serde_yaml::from_str::<serde_yaml::Value>(content)
            .with_context(|| format!("failed to parse YAML for LOLC2: {path}"))?
    };

    let mut entries = Vec::new();
    match value {
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                if let Some((keys, info)) = build_lolc2_info(path, &item) {
                    for key in keys {
                        entries.push((key, info.clone()));
                    }
                }
            }
        }
        serde_yaml::Value::Mapping(_) => {
            if let Some((keys, info)) = build_lolc2_info(path, &value) {
                for key in keys {
                    entries.push((key, info.clone()));
                }
            }
        }
        _ => {}
    }

    Ok(entries)
}

fn build_lot_tunnel_info(
    path: &str,
    value: &serde_yaml::Value,
) -> Option<(Vec<String>, TunnelToolInfo)> {
    let name = yaml_string_for_keys(
        value,
        &[
            "name", "title", "tool", "binary", "process", "command", "slug",
        ],
    )
    .or_else(|| {
        Path::new(path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_string)
    })?;

    let description =
        yaml_string_for_keys(value, &["description", "summary", "about"]).unwrap_or_default();

    let mut capabilities = yaml_string_vec_for_keys(
        value,
        &[
            "capabilities",
            "tags",
            "use_cases",
            "uses",
            "features",
            "techniques",
        ],
    );
    if capabilities.is_empty() {
        for key in ["capabilities", "uses", "usage", "functions", "categories"] {
            if let Some(serde_yaml::Value::Mapping(mapping)) = yaml_value_for_key(value, key) {
                for map_key in mapping.keys() {
                    if let Some(text) = map_key.as_str() {
                        let normalized = normalize_capability_token(text);
                        if !normalized.is_empty() {
                            capabilities.push(normalized);
                        }
                    }
                }
            }
        }
    }
    capabilities.sort();
    capabilities.dedup();

    let mut keys = vec![normalize_process_name(&name)];
    keys.extend(yaml_string_vec_for_keys(
        value,
        &[
            "binary",
            "binaries",
            "process",
            "processes",
            "command",
            "commands",
            "aliases",
            "alias",
        ],
    ));
    keys = keys
        .into_iter()
        .map(|item| normalize_process_name(&item))
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    if keys.is_empty() {
        return None;
    }

    Some((
        keys,
        TunnelToolInfo {
            name,
            description,
            capabilities,
        },
    ))
}

fn build_lolc2_info(path: &str, value: &serde_yaml::Value) -> Option<(Vec<String>, C2ToolInfo)> {
    let name = yaml_string_for_keys(
        value,
        &[
            "name",
            "title",
            "tool",
            "binary",
            "framework",
            "project",
            "slug",
        ],
    )
    .or_else(|| {
        Path::new(path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_string)
    })?;

    let description =
        yaml_string_for_keys(value, &["description", "summary", "about"]).unwrap_or_default();

    let mut abused_services = yaml_string_vec_for_keys(
        value,
        &[
            "abused_services",
            "legitimate_services",
            "services",
            "service",
            "platforms",
            "channels",
            "transports",
            "communication",
            "comms",
            "tags",
        ],
    );
    if abused_services.is_empty() {
        for key in [
            "abused_services",
            "services",
            "service",
            "platforms",
            "channels",
        ] {
            if let Some(serde_yaml::Value::Mapping(mapping)) = yaml_value_for_key(value, key) {
                for map_key in mapping.keys() {
                    if let Some(text) = map_key.as_str() {
                        let normalized = normalize_capability_token(text);
                        if !normalized.is_empty() {
                            abused_services.push(normalized);
                        }
                    }
                }
            }
        }
    }
    abused_services.sort();
    abused_services.dedup();

    let mut reference_candidates = yaml_string_vec_for_keys(
        value,
        &[
            "reference",
            "references",
            "reference_url",
            "url",
            "urls",
            "website",
            "source",
            "repo",
            "github",
        ],
    );
    let reference_url = reference_candidates
        .drain(..)
        .find(|candidate| candidate.starts_with("http://") || candidate.starts_with("https://"))
        .unwrap_or_else(|| format!("https://github.com/lolc2/lolc2.github.io/blob/main/{path}"));

    let mut keys = vec![normalize_process_name(&name)];
    keys.extend(yaml_string_vec_for_keys(
        value,
        &[
            "binary",
            "binaries",
            "process",
            "processes",
            "command",
            "commands",
            "aliases",
            "alias",
            "tool",
        ],
    ));
    keys = keys
        .into_iter()
        .map(|item| normalize_process_name(&item))
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    if keys.is_empty() {
        return None;
    }

    Some((
        keys,
        C2ToolInfo {
            name,
            description,
            abused_services,
            reference_url,
        },
    ))
}

fn yaml_string_for_keys(value: &serde_yaml::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| yaml_value_for_key(value, key))
        .and_then(yaml_value_as_string)
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn yaml_string_vec_for_keys(value: &serde_yaml::Value, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for key in keys {
        if let Some(found) = yaml_value_for_key(value, key) {
            out.extend(yaml_value_as_string_vec(found));
        }
    }
    out.into_iter()
        .map(|item| normalize_capability_token(&item))
        .filter(|item| !item.is_empty())
        .collect()
}

fn normalize_capability_token(input: &str) -> String {
    input
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase()
}

fn yaml_value_for_key<'a>(
    value: &'a serde_yaml::Value,
    key: &str,
) -> Option<&'a serde_yaml::Value> {
    let serde_yaml::Value::Mapping(map) = value else {
        return None;
    };
    let direct_key = serde_yaml::Value::String(key.to_string());
    map.get(&direct_key).or_else(|| {
        map.iter().find_map(|(map_key, map_value)| {
            map_key
                .as_str()
                .filter(|candidate| candidate.eq_ignore_ascii_case(key))
                .map(|_| map_value)
        })
    })
}

fn yaml_value_as_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(text) => Some(text.to_string()),
        serde_yaml::Value::Number(number) => Some(number.to_string()),
        serde_yaml::Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn yaml_value_as_string_vec(value: &serde_yaml::Value) -> Vec<String> {
    match value {
        serde_yaml::Value::Sequence(items) => items
            .iter()
            .filter_map(yaml_value_as_string)
            .collect::<Vec<_>>(),
        serde_yaml::Value::Mapping(map) => map
            .keys()
            .filter_map(serde_yaml::Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>(),
        _ => yaml_value_as_string(value).into_iter().collect(),
    }
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
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
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
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
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
        assert!(
            manager
                .check_file_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .is_some()
        );
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
    fn parses_gtfobins_functions_from_front_matter() {
        let sample = r#"---
functions:
  shell:
    - description: It can be used to break out.
      code: python -c "import os; os.system(\"/bin/sh\")"
  reverse-shell:
    - description: Connect back
      code: python -c "..."
  file-write:
    - description: Write file
      code: python -c "..."
---
body
"#;

        let parsed = parse_gtfobin_functions(sample).expect("GTFOBins functions should parse");
        assert_eq!(
            parsed,
            vec![
                "file-write".to_string(),
                "reverse-shell".to_string(),
                "shell".to_string()
            ]
        );
    }

    #[test]
    fn check_gtfobin_matches_python() {
        let mut manager = DatasetManager::default();
        manager.gtfobins.insert(
            "python".to_string(),
            GtfobinInfo {
                name: "python".to_string(),
                functions: vec!["shell".to_string(), "suid".to_string()],
            },
        );

        let python = manager
            .check_gtfobin("Python")
            .expect("python should be indexed");
        assert!(python.functions.contains(&"shell".to_string()));
    }

    #[test]
    fn parses_lot_tunnel_front_matter_entry() {
        let sample = r#"---
name: ngrok
description: Expose local services to the Internet.
capabilities:
  - c2
  - reverse shell
binaries:
  - ngrok
---
# ngrok
"#;

        let parsed = parse_lot_tunnel_entries("_tunnels/ngrok.md", sample)
            .expect("LOT Tunnels sample should parse");
        assert!(!parsed.is_empty());
        let info = parsed
            .iter()
            .find_map(|(key, info)| (key == "ngrok").then_some(info))
            .expect("ngrok key should exist");
        assert_eq!(info.name, "ngrok");
        assert!(info.capabilities.iter().any(|cap| cap == "c2"));
    }

    #[test]
    fn check_tunnel_tool_matches_common_names() {
        let mut manager = DatasetManager::default();
        for name in ["ngrok", "cloudflared", "chisel"] {
            manager.tunnels.insert(
                name.to_string(),
                TunnelToolInfo {
                    name: name.to_string(),
                    description: "Tunnel utility".to_string(),
                    capabilities: vec!["c2".to_string(), "exfiltration".to_string()],
                },
            );
        }

        assert!(manager.check_tunnel_tool("ngrok").is_some());
        assert!(manager.check_tunnel_tool("cloudflared").is_some());
        assert!(manager.check_tunnel_tool("chisel").is_some());
        assert!(manager.check_tunnel_tool("CHISEL.EXE").is_some());
    }

    #[test]
    fn parses_lolc2_front_matter_entry() {
        let sample = r#"---
name: sliver
description: C2 framework that can leverage common SaaS channels.
abused_services:
  - discord
  - slack
binaries:
  - sliver-server
reference_url: https://lolc2.github.io/#/tool?id=sliver
---
content
"#;

        let parsed =
            parse_lolc2_entries("c2/sliver.md", sample).expect("LOLC2 sample should parse");
        assert!(!parsed.is_empty());
        let info = parsed
            .iter()
            .find_map(|(key, info)| (key == "sliver-server").then_some(info))
            .expect("sliver-server key should exist");
        assert_eq!(info.name, "sliver");
        assert!(
            info.abused_services
                .iter()
                .any(|service| service == "discord")
        );
        assert_eq!(
            info.reference_url,
            "https://lolc2.github.io/#/tool?id=sliver"
        );
    }

    #[test]
    fn check_c2_tool_matches_common_names() {
        let mut manager = DatasetManager::default();
        manager.c2_tools.insert(
            "sliver".to_string(),
            C2ToolInfo {
                name: "sliver".to_string(),
                description: "C2 framework".to_string(),
                abused_services: vec!["discord".to_string(), "slack".to_string()],
                reference_url: "https://lolc2.github.io/".to_string(),
            },
        );

        assert!(manager.check_c2_tool("sliver").is_some());
        assert!(manager.check_c2_tool("SLIVER.EXE").is_some());
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
