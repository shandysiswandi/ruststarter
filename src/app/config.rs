//! A robust, thread-safe, and auto-reloading configuration management module.
//!
//! This module provides a `Config` struct for loading settings from a file.
//! It uses a builder pattern for clear initialization and can be configured to
//! watch the source file for changes, automatically reloading the configuration
//! in the background. It is designed to be safe for use in concurrent applications.

use config::{Config as RawConfig, File};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, mpsc};
use std::thread;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to load or parse configuration file")]
    Load(#[from] config::ConfigError),

    #[error("Failed to initialize file watcher")]
    Watch(#[from] notify::Error),

    #[error("Configuration lock was poisoned, indicating a panic in another thread")]
    LockPoisoned,
}

#[derive(Debug)]
pub struct Config {
    // The configuration state is wrapped in an Arc<RwLock> to allow for
    // concurrent reads and exclusive writes across multiple threads.
    inner: Arc<RwLock<RawConfig>>,
    // The file watcher is stored here. When `Config` is dropped, the watcher
    // is also dropped, automatically stopping the watch thread.
    _watcher: Option<RecommendedWatcher>,
}

impl Config {
    pub fn builder<P: AsRef<Path>>(path: P) -> ConfigBuilder {
        ConfigBuilder::new(path.as_ref().to_path_buf())
    }

    #[cfg(test)]
    pub fn builder_test() -> test_utils::TestConfigBuilder {
        test_utils::TestConfigBuilder::new()
    }

    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<T, ConfigError> {
        let guard = self.inner.read().map_err(|_| ConfigError::LockPoisoned)?;
        guard.get(key).map_err(ConfigError::from)
    }
}

pub struct ConfigBuilder {
    path: PathBuf,
    watch: bool,
    watch_interval: Duration,
}

impl ConfigBuilder {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            watch: false,
            watch_interval: Duration::from_secs(2),
        }
    }

    pub fn watch(mut self) -> Self {
        self.watch = true;
        self
    }

    pub fn watch_interval(mut self, interval: Duration) -> Self {
        self.watch_interval = interval;
        self
    }

    pub fn build(self) -> Result<Config, ConfigError> {
        let raw_config = Self::load(&self.path)?;
        let config_arc = Arc::new(RwLock::new(raw_config));
        let mut watcher = None;

        if self.watch {
            let path_clone = self.path.clone();
            let config_clone = Arc::clone(&config_arc);
            let (tx, rx) = mpsc::channel();

            let mut w = RecommendedWatcher::new(
                tx,
                notify::Config::default().with_poll_interval(self.watch_interval),
            )?;
            w.watch(&self.path, RecursiveMode::NonRecursive)?;

            thread::spawn(move || {
                tracing::info!(
                    "Watching configuration file for changes: {}",
                    &path_clone.to_string_lossy()
                );
                while let Ok(event_result) = rx.recv() {
                    match event_result {
                        Ok(Event {
                            kind: notify::EventKind::Modify(_),
                            ..
                        }) => {
                            tracing::info!("Configuration file changed. Reloading...");
                            match Self::load(&path_clone) {
                                Ok(new_config) => {
                                    if let Ok(mut guard) = config_clone.write() {
                                        *guard = new_config;
                                        tracing::info!("Configuration reloaded successfully.");
                                    } else {
                                        tracing::error!("Failed to acquire write lock for reloading config.");
                                    }
                                },
                                Err(e) => {
                                    tracing::error!("Failed to reload configuration file: {}", e);
                                },
                            }
                        },
                        Err(e) => tracing::error!("File watcher error: {:?}", e),
                        _ => {
                            // Ignore other event types (e.g., Access, Open, etc.)
                        },
                    }
                }
            });
            watcher = Some(w);
        }

        Ok(Config {
            inner: config_arc,
            _watcher: watcher,
        })
    }

    fn load(path: &Path) -> Result<RawConfig, config::ConfigError> {
        RawConfig::builder()
            .add_source(File::from(path).required(true))
            .build()
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use config::Value;
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct TestConfigBuilder {
        values: HashMap<String, Value>,
    }

    impl TestConfigBuilder {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn with<T: Into<Value>>(mut self, key: &str, value: T) -> Self {
            self.values.insert(key.to_string(), value.into());
            self
        }

        pub fn build(self) -> Config {
            let mut builder = RawConfig::builder();

            for (key, value) in self.values {
                builder = builder.set_override(key, value).unwrap();
            }

            let raw_config = builder.build().expect("Failed to create config from test values");

            Config {
                inner: Arc::new(RwLock::new(raw_config)),
                _watcher: None,
            }
        }
    }
}
