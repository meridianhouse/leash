use crate::config::Config;
use crate::mitre;
use crate::models::{EventType, FileEvent, SecurityEvent, ThreatLevel};
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
}

impl FileIntegrityMonitor {
    pub fn new(
        cfg: Config,
        tx: broadcast::Sender<SecurityEvent>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            cfg,
            tx,
            hashes: HashMap::new(),
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

        let paths: Vec<PathBuf> = self.cfg.fim_paths.iter().map(PathBuf::from).collect();
        for path in &paths {
            if !path.exists() {
                continue;
            }
            if let Err(err) = self.seed_baseline(path) {
                warn!(?err, path = %path.display(), "failed to baseline path");
            }
            if let Err(err) = watcher.watch(path, RecursiveMode::Recursive) {
                warn!(?err, path = %path.display(), "failed to watch path");
            }
        }

        while let Some(msg) = notify_rx.recv().await {
            match msg {
                Ok(event) => {
                    for path in event.paths {
                        if let Some(sec) = self.convert_event(&path, &event.kind) {
                            let _ = self.tx.send(sec);
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
            if let Some(hash) = hash_file(path) {
                self.hashes.insert(path.display().to_string(), hash);
            }
            return Ok(());
        }

        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                let _ = self.seed_baseline(&p);
            } else if let Some(hash) = hash_file(&p) {
                self.hashes.insert(p.display().to_string(), hash);
            }
        }
        Ok(())
    }

    fn convert_event(&mut self, path: &Path, kind: &EventKind) -> Option<SecurityEvent> {
        let key = path.display().to_string();
        let previous = self.hashes.get(&key).cloned();
        let current = hash_file(path);

        let (event_type, label, level) = match kind {
            EventKind::Create(_) => (EventType::FileCreated, "created", ThreatLevel::Yellow),
            EventKind::Modify(_) => (EventType::FileModified, "modified", ThreatLevel::Yellow),
            EventKind::Remove(_) => (EventType::FileModified, "deleted", ThreatLevel::Orange),
            _ => return None,
        };

        match &current {
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
            new_hash: current,
            old_perms: None,
            new_perms: path.metadata().ok().map(|m| m.permissions().mode()),
        };

        let mut event =
            SecurityEvent::new(event_type, level, format!("Sensitive file {label}: {key}"));
        event.file_event = Some(file_event);
        Some(mitre::infer_and_tag(event))
    }
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn hash_file(path: &Path) -> Option<String> {
    let data = fs::read(path).ok()?;
    let mut hasher = Hasher::new();
    hasher.update(&data);
    Some(hasher.finalize().to_hex().to_string())
}
