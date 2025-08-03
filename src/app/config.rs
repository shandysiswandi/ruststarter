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
                tracing::info!("Watching configuration file for changes: {:?}", &path_clone);
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
                                        tracing::error!(
                                            "Failed to acquire write lock for reloading config."
                                        );
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
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;

    /// Helper function to create a temporary config file for testing.
    fn setup_temp_config(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("settings.yaml");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{content}").unwrap();
        (dir, file_path)
    }

    #[test]
    fn get_value_succeeds_for_existing_key() {
        // Arrange
        let (_dir, config_path) = setup_temp_config("server_port: 8080");
        let config = Config::builder(config_path).build().unwrap();

        // Act
        let port: u16 = config.get("server_port").unwrap();

        // Assert
        assert_eq!(port, 8080);
    }

    #[test]
    fn get_value_fails_for_missing_key() {
        // Arrange
        let (_dir, config_path) = setup_temp_config("server_port: 8080");
        let config = Config::builder(config_path).build().unwrap();

        // Act
        let result: Result<String, _> = config.get("database_url");

        // Assert
        assert!(result.is_err());
        // Match on the error variant instead of the string for a more robust test.
        assert!(matches!(
            result.err().unwrap(),
            ConfigError::Load(config::ConfigError::NotFound(_))
        ));
    }

    #[test]
    fn build_fails_for_nonexistent_file() {
        // Arrange
        let path = PathBuf::from("nonexistent/config.yaml");

        // Act
        let result = Config::builder(path).build();

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn watcher_reloads_configuration_on_change() {
        // Arrange
        let initial_content = "log_level: 'info'";
        let (_dir, config_path) = setup_temp_config(initial_content);

        let config = Config::builder(&config_path)
            .watch()
            .watch_interval(Duration::from_millis(100))
            .build()
            .unwrap();

        // Act & Assert 1: Check initial value
        assert_eq!(config.get::<String>("log_level").unwrap(), "info");

        // Act 2: Modify the file
        let updated_content = "log_level: 'debug'";
        fs::write(&config_path, updated_content).unwrap();

        // Allow time for the watcher to detect the change and reload
        thread::sleep(Duration::from_millis(500));

        // Assert 2: Check reloaded value
        assert_eq!(config.get::<String>("log_level").unwrap(), "debug");
    }
}
