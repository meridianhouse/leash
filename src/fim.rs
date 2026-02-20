use crate::config::Config;
use crate::datasets::{DatasetManager, compute_sha256_hex};
use crate::mitre;
use crate::models::{EventType, FileEvent, SecurityEvent, ThreatLevel};
use crate::stats;
use blake3::Hasher;
use notify::{Config as NotifyConfig, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, warn};

pub struct FileIntegrityMonitor {
    cfg: Config,
    tx: broadcast::Sender<SecurityEvent>,
    hashes: HashMap<String, String>,
    datasets: Option<DatasetManager>,
}

impl FileIntegrityMonitor {
    pub fn new(
        cfg: Config,
        tx: broadcast::Sender<SecurityEvent>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let datasets = if cfg.datasets.enabled {
            let cache_dir = Path::new(&cfg.datasets.cache_dir);
            match DatasetManager::load_cache(cache_dir) {
                Ok(manager) => Some(manager),
                Err(err) => {
                    warn!(
                        ?err,
                        path = %cache_dir.display(),
                        "failed to load datasets cache; LOLDrivers file matching disabled until cache is initialized"
                    );
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            cfg,
            tx,
            hashes: HashMap::new(),
            datasets,
        })
    }

    pub async fn run(mut self) {
        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();

        let mut watcher = match RecommendedWatcher::new(
            move |res| {
                let _ = notify_tx.send(res);
            },
            NotifyConfig::default(),
        ) {
            Ok(w) => w,
            Err(err) => {
                error!(?err, "failed to create file watcher");
                return;
            }
        };

        let raw_paths: Vec<PathBuf> = self.cfg.fim_paths.iter().map(PathBuf::from).collect();
        for path in &raw_paths {
            let canonical = match fs::canonicalize(path) {
                Ok(resolved) => resolved,
                Err(err) => {
                    warn!(
                        ?err,
                        path = %path.display(),
                        "failed to canonicalize FIM path; skipping watch"
                    );
                    continue;
                }
            };
            if !canonical.exists() {
                continue;
            }
            if let Err(err) = self.seed_baseline(&canonical) {
                warn!(?err, path = %canonical.display(), "failed to baseline path");
            }
            if let Err(err) = watcher.watch(&canonical, RecursiveMode::Recursive) {
                warn!(?err, path = %canonical.display(), "failed to watch path");
            }
        }

        while let Some(msg) = notify_rx.recv().await {
            match msg {
                Ok(event) => {
                    for path in event.paths {
                        if let Some(sec) = self.convert_event(&path, &event.kind) {
                            if let Err(err) = self.tx.send(sec) {
                                stats::record_dropped_event();
                                warn!(
                                    event_type = %err.0.event_type,
                                    "dropping event: broadcast channel full or closed"
                                );
                            }
                        }
                    }
                }
                Err(err) => warn!(?err, "notify event error"),
            }
        }
    }

    fn seed_baseline(
        &mut self,
        path: &Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if path.is_file() {
            if let Some(hashes) = hash_file(path) {
                self.hashes
                    .insert(path.display().to_string(), hashes.blake3_hex);
            }
            return Ok(());
        }

        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                let _ = self.seed_baseline(&p);
            } else if let Some(hashes) = hash_file(&p) {
                self.hashes.insert(p.display().to_string(), hashes.blake3_hex);
            }
        }
        Ok(())
    }

    fn convert_event(&mut self, path: &Path, kind: &EventKind) -> Option<SecurityEvent> {
        let key = path.display().to_string();
        let previous = self.hashes.get(&key).cloned();
        let current_hashes = hash_file(path);
        let current_blake3 = current_hashes.as_ref().map(|h| h.blake3_hex.clone());

        let (event_type, label, level) = match kind {
            EventKind::Create(_) => (EventType::FileCreated, "created", ThreatLevel::Yellow),
            EventKind::Modify(_) => (EventType::FileModified, "modified", ThreatLevel::Yellow),
            EventKind::Remove(_) => (EventType::FileModified, "deleted", ThreatLevel::Orange),
            _ => return None,
        };

        match &current_blake3 {
            Some(hash) => {
                self.hashes.insert(key.clone(), hash.clone());
            }
            None => {
                self.hashes.remove(&key);
            }
        }

        let file_event = FileEvent {
            path: key.clone(),
            event_type: label.to_string(),
            old_hash: previous,
            new_hash: current_blake3,
            old_perms: None,
            new_perms: path.metadata().ok().map(|m| m.permissions().mode()),
        };

        let mut event =
            SecurityEvent::new(event_type, level, format!("Sensitive file {label}: {key}"));
        event.file_event = Some(file_event.clone());

        if matches!(kind, EventKind::Create(_) | EventKind::Modify(_))
            && let Ok(content) = fs::read_to_string(path)
            && let Some(injection_event) =
                crate::prompt_injection::scan_file_for_injection(&key, &content)
        {
            if let Err(err) = self.tx.send(injection_event) {
                stats::record_dropped_event();
                warn!(
                    event_type = %err.0.event_type,
                    "dropping event: broadcast channel full or closed"
                );
            }
        }

        if matches!(kind, EventKind::Create(_) | EventKind::Modify(_))
            && let (Some(datasets), Some(hashes)) = (&self.datasets, &current_hashes)
        {
            let filename = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            let driver_match = datasets
                .check_file_hash(&hashes.sha256_hex)
                .or_else(|| datasets.check_driver_name(filename));
            if let Some(driver) = driver_match {
                let mut driver_event = SecurityEvent::new(
                    EventType::LolDriverMatch,
                    ThreatLevel::Red,
                    format!(
                        "LOLDrivers vulnerable driver detected: file={} category={} reference={}",
                        filename, driver.category, driver.reference_url
                    ),
                );
                driver_event.file_event = Some(file_event.clone());
                if let Err(err) = self.tx.send(mitre::infer_and_tag(driver_event)) {
                    stats::record_dropped_event();
                    warn!(
                        event_type = %err.0.event_type,
                        "dropping event: broadcast channel full or closed"
                    );
                }
            }
        }

        Some(mitre::infer_and_tag(event))
    }
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

struct FileHashes {
    blake3_hex: String,
    sha256_hex: String,
}

fn hash_file(path: &Path) -> Option<FileHashes> {
    let data = fs::read(path).ok()?;
    let mut hasher = Hasher::new();
    hasher.update(&data);
    Some(FileHashes {
        blake3_hex: hasher.finalize().to_hex().to_string(),
        sha256_hex: compute_sha256_hex(&data),
    })
}
