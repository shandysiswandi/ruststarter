//! The binary entry point for the application.

use std::sync::Arc;
use std::time::Duration;

use app_core::config::Config;
use app_core::crypto::AesSecretCrypto;
use app_core::jwt::{JwtConfig, JwtService, TokenManager};
use app_core::mail::local as mail_local;
use app_core::middleware::request_response_logger;
use app_core::oauth::{GoogleOAuthProvider, OAuthManager};
use app_core::password::{Argon2Hasher, Hasher};
use app_core::storage::StorageService;
use app_core::storage::local::LocalStorageService;
use app_core::uid::{Generator, Snowflake};
use auth;
use axum::http::StatusCode;
use axum::{Json, Router, middleware, routing};
use base64::Engine as _;
use base64::engine::general_purpose;
use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use sea_orm::{ConnectOptions, Database};
use tokio::signal;
use tokio::sync::broadcast;
use tower::ServiceBuilder;
use tower_cookies::{CookieManagerLayer, Key};
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::decompression::RequestDecompressionLayer;
use tower_http::timeout::TimeoutLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(
            fmt::layer()
                .json()
                .with_target(true)
                .with_file(true)
                .with_line_number(true)
                .with_span_events(fmt::format::FmtSpan::CLOSE),
        )
        .init();

    if let Err(err) = run().await {
        panic!("❌ Application failed to start: {err}");
    }
}

/// Initializes all dependencies and starts the web server.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize configuration and watcher.
    // The .watch() method enables automatic reloading when the config file changes.
    let config = Arc::new(
        Config::builder("config/config.yaml")
            .watch_interval(Duration::from_secs(5))
            .watch()
            .build()?,
    );

    // Initialize the SeaORM database connection pool.
    let mut db_opt = ConnectOptions::new(config.get::<String>("database.url")?);
    db_opt
        .min_connections(config.get("database.min_connections")?)
        .max_connections(config.get("database.max_connections")?)
        .connect_timeout(Duration::from_secs(config.get("database.connect_timeout_secs")?))
        .acquire_timeout(Duration::from_secs(config.get("database.acquire_timeout_secs")?))
        .idle_timeout(Duration::from_secs(config.get("database.idle_timeout_secs")?))
        .max_lifetime(Duration::from_secs(config.get("database.max_lifetime_secs")?))
        .sqlx_logging(config.get("database.sqlx_logging")?)
        .sqlx_logging_level(log::LevelFilter::Debug);

    let db_pool = Arc::new(Database::connect(db_opt).await?);

    // Initialize redis connection pool.
    let rds_url = config.get::<String>("redis.url")?;
    let rds_manager = RedisConnectionManager::new(rds_url)?;
    let rds_pool = Pool::builder()
        .max_size(config.get::<u32>("database.max_connections")?)
        .build(rds_manager)
        .await?;

    // Initialize mail connection.
    let mail_host = config.get::<String>("mail.host")?;
    let mail_port = config.get::<u16>("mail.port")?;
    let mail_from = config.get::<String>("mail.from")?;
    let smtp_mail = Arc::new(mail_local::SmtpMailer::new(mail_host.as_ref(), mail_port, mail_from));

    // Initialize the Snowflake ID generator.
    let snowflake: Arc<dyn Generator> = Arc::new(
        Snowflake::builder(config.get("snowflake.worker_id")?)
            .with_epoch(config.get("snowflake.epoch")?)
            .build()?,
    );

    // Initialize the Argon2id hasher.
    let hasher: Arc<dyn Hasher> = Arc::new(Argon2Hasher::new());

    // Initialize the Aes crypto
    let crypto = Arc::new(AesSecretCrypto::new(config.get("crypto.secret")?, config.get("crypto.salt")?));

    // Instantiate the JWT service with all required config values.
    let token_manager: Arc<dyn TokenManager> = Arc::new(JwtService::new(JwtConfig {
        access_secret: config.get("jwt.access_secret")?,
        refresh_secret: config.get("jwt.refresh_secret")?,
        generic_secret: config.get("jwt.generic_secret")?,
        access_exp_secs: config.get("jwt.access_expiration_secs")?,
        refresh_exp_secs: config.get("jwt.refresh_expiration_secs")?,
        generic_exp_secs: config.get("jwt.generic_expiration_secs")?,
        issuer: config.get("jwt.issuer")?,
        audience: config.get("jwt.audience")?,
    }));

    // Initialize the cookie encryption key.
    let cookie_key = Key::from(&general_purpose::STANDARD.decode(config.get::<String>("session.secret")?)?);

    // Initialize OAuth Manager and providers.
    let mut oauth_manager = OAuthManager::new();
    if let Ok(client_id) = config.get::<String>("oauth.google.client_id") {
        let client_secret = config.get("oauth.google.client_secret")?;
        let redirect_uri = config.get("oauth.google.redirect_uri")?;
        let google_provider = GoogleOAuthProvider::new(client_id, client_secret, redirect_uri)?;
        oauth_manager.add_provider("google", Arc::new(google_provider));
    }

    // Initialize the storage service.
    let base_path = config.get("storage.local.base_path")?;
    let base_url = config.get("storage.local.base_url")?;
    let storage_service: Arc<dyn StorageService> = Arc::new(LocalStorageService::new(base_path, base_url));

    // Initialize auth module
    let auth_state = auth::new(auth::Dependency {
        db: db_pool.clone(),
        rds: rds_pool,
        config: config.clone(),
        uid: snowflake,
        hasher,
        crypto,
        token: token_manager.clone(),
        mail: smtp_mail,
        storage: storage_service,
        oauth: oauth_manager,
        cookie_key,
    });

    // Create the Router and Middlewares
    let timeout_secs = Duration::from_secs(config.get::<u64>("server.timeout_secs")?);
    let app = Router::new()
        .merge(auth::create_router(auth_state, token_manager.clone()))
        .route(
            "/",
            routing::get(|| async { Json(serde_json::json!({"message": "Hello from Rust Starter"})) }),
        )
        .fallback(|| async {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"message": "Endpoint not found"})),
            )
        })
        .method_not_allowed_fallback(|| async {
            (
                StatusCode::METHOD_NOT_ALLOWED,
                Json(serde_json::json!({"message": "Method not allowed"})),
            )
        })
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(request_response_logger))
                .layer(CookieManagerLayer::new())
                .layer(CorsLayer::new().allow_origin(Any).allow_headers(Any)) // Enables CORS for all origins
                .layer(RequestDecompressionLayer::new()) // Enables request compression
                .layer(CompressionLayer::new()) // Enables response compression
                .layer(TimeoutLayer::new(timeout_secs)), // Adds a request timeout
        );

    let server_address = config.get::<String>("server.address")?;
    let listener = tokio::net::TcpListener::bind(&server_address).await?;

    tracing::info!("🚀 listening on {}", listener.local_addr()?);

    // Create a broadcast channel to signal shutdown to all application components.
    // Spawn a task to listen for shutdown signals (Ctrl+C and SIGTERM).
    let (shutdown_tx, _) = broadcast::channel(1);
    spawn_shutdown_listener(shutdown_tx.clone());

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_tx.subscribe().recv().await.ok();
            tracing::info!("🛑 Server is shutting down gracefully...");
        })
        .await?;

    // close / drop all holding resources
    // Arc::try_unwrap(db_pool)
    //     .map_err(|_| "Failed to close database - references still exist")?
    //     .close()
    //     .await?;

    Ok(())
}

/// Spawns a background task to listen for system shutdown signals.
fn spawn_shutdown_listener(shutdown_tx: broadcast::Sender<()>) {
    tokio::spawn(async move {
        let ctrl_c = async {
            signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => { tracing::info!("🔻 Received SIGINT (Ctrl+C)")},
            _ = terminate => { tracing::info!("🔻 Received SIGTERM")},
        }

        // Send the shutdown signal to all parts of the application.
        if shutdown_tx.send(()).is_err() {
            tracing::error!("Failed to send shutdown signal");
        }
    });
}
