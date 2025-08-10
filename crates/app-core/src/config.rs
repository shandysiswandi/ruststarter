//! A robust, thread-safe, and auto-reloading configuration management module.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, mpsc};
use std::thread;
use std::time::Duration;

use config::{Config as RawConfig, File};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::de::DeserializeOwned;
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

    #[cfg(feature = "testing")]
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
        Self { path, watch: false, watch_interval: Duration::from_secs(2) }
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

            let mut w = RecommendedWatcher::new(tx, notify::Config::default().with_poll_interval(self.watch_interval))?;
            w.watch(&self.path, RecursiveMode::NonRecursive)?;

            thread::spawn(move || {
                tracing::info!("Watching configuration file for changes: {}", &path_clone.to_string_lossy());
                while let Ok(event_result) = rx.recv() {
                    match event_result {
                        Ok(Event { kind: notify::EventKind::Modify(_), .. }) => {
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
                            // Ignore other event types (e.g., Access, Open,
                            // etc.)
                        },
                    }
                }
            });
            watcher = Some(w);
        }

        Ok(Config { inner: config_arc, _watcher: watcher })
    }

    fn load(path: &Path) -> Result<RawConfig, config::ConfigError> {
        RawConfig::builder().add_source(File::from(path).required(true)).build()
    }
}

#[cfg(feature = "testing")]
pub mod test_utils {
    use std::collections::HashMap;

    use config::Value;

    use super::*;

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

            Config { inner: Arc::new(RwLock::new(raw_config)), _watcher: None }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use serde::Deserialize;
    use tempfile::NamedTempFile;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    struct TestSettings {
        app_name: String,
        port: u16,
        debug: bool,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct DatabaseConfig {
        host: String,
        port: u16,
        name: String,
    }

    /// Helper function to create a temporary config file with YAML content
    fn create_temp_config(content: &str) -> NamedTempFile {
        let mut temp_file = tempfile::Builder::new()
            .suffix(".yaml")
            .tempfile()
            .expect("Failed to create temp file");

        temp_file.write_all(content.as_bytes()).expect("Failed to write to temp file");
        temp_file.flush().expect("Failed to flush temp file");
        temp_file
    }

    #[test]
    fn test_builder_basic_usage() {
        let config_content = r#"
            app_name: "test_app"
            port: 8080
            debug: true
            database:
                host: "localhost"
                port: 5432
                name: "test_db"
        "#;

        let temp_file = create_temp_config(config_content);
        let config = Config::builder(temp_file.path()).build().expect("Failed to build config");

        let app_name: String = config.get("app_name").expect("Failed to get app_name");
        let port: u16 = config.get("port").expect("Failed to get port");
        let debug: bool = config.get("debug").expect("Failed to get debug");

        let db_config: DatabaseConfig = config.get("database").expect("Failed to get database config");

        assert_eq!(app_name, "test_app");
        assert_eq!(port, 8080);
        assert_eq!(debug, true);

        assert_eq!(db_config.host, "localhost");
        assert_eq!(db_config.port, 5432);
        assert_eq!(db_config.name, "test_db");
    }

    #[test]
    fn test_nonexistent_file() {
        let result = Config::builder("/nonexistent/path/config.yaml").build();

        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Load(_) => {}, // Expected error type
            other => panic!("Expected ConfigError::Load, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_yaml() {
        let invalid_content = r#"
            app_name: "test
            port: [invalid: yaml
        "#;

        let temp_file = create_temp_config(invalid_content);
        let result = Config::builder(temp_file.path()).build();

        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Load(_) => {}, // Expected error type
            other => panic!("Expected ConfigError::Load, got {:?}", other),
        }
    }

    #[test]
    fn test_missing_key() {
        let config_content = r#"
            app_name: "test_app"
        "#;

        let temp_file = create_temp_config(config_content);
        let config = Config::builder(temp_file.path()).build().expect("Failed to build config");

        let result = config.get::<i32>("nonexistent_key");
        assert!(result.is_err());
    }

    #[test]
    fn test_with_watch_no_changes() {
        let config_content = r#"
            app_name: "watch_test"
            port: 9000
        "#;

        let temp_file = create_temp_config(config_content);
        let config = Config::builder(temp_file.path())
            .watch()
            .watch_interval(Duration::from_millis(100))
            .build()
            .expect("Failed to build config with watch");

        let app_name: String = config.get("app_name").expect("Failed to get app_name");
        assert_eq!(app_name, "watch_test");

        // Give the watcher a moment to start
        thread::sleep(Duration::from_millis(150));

        let app_name_after: String = config.get("app_name").expect("Failed to get app_name");
        assert_eq!(app_name_after, "watch_test");
    }

    #[test]
    fn test_auto_reload() {
        let initial_content = r#"
            app_name: "initial_app"
            port: 8000
        "#;

        let temp_file = create_temp_config(initial_content);
        let config = Config::builder(temp_file.path())
            .watch()
            .watch_interval(Duration::from_millis(100))
            .build()
            .expect("Failed to build config with watch");

        let initial_name: String = config.get("app_name").expect("Failed to get initial app_name");
        assert_eq!(initial_name, "initial_app");

        let updated_content = r#"
            app_name: "updated_app"
            port: 8001
        "#;

        fs::write(temp_file.path(), updated_content).expect("Failed to update config file");

        // Wait for the file watcher to detect changes and reload
        thread::sleep(Duration::from_millis(500));

        let updated_name: String = config.get("app_name").expect("Failed to get updated app_name");
        assert_eq!(updated_name, "updated_app");

        let updated_port: u16 = config.get("port").expect("Failed to get updated port");
        assert_eq!(updated_port, 8001);
    }

    #[test]
    fn test_builder_test() {
        let config = Config::builder_test()
            .with("app_name", "test_app")
            .with("port", 3000)
            .with("debug", true)
            .with("database.host", "localhost")
            .with("database.port", 5432)
            .with("database.name", "test_db")
            .build();

        let app_name: String = config.get("app_name").expect("Failed to get app_name");
        let port: i32 = config.get("port").expect("Failed to get port");
        let debug: bool = config.get("debug").expect("Failed to get debug");
        //
        let host: String = config.get("database.host").expect("Failed to get database host");
        let db_port: i32 = config.get("database.port").expect("Failed to get database port");
        let name: String = config.get("database.name").expect("Failed to get database name");

        assert_eq!(app_name, "test_app");
        assert_eq!(port, 3000);
        assert_eq!(debug, true);
        //
        assert_eq!(host, "localhost");
        assert_eq!(db_port, 5432);
        assert_eq!(name, "test_db");
    }
}
