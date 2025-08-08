use crate::app::config::Config;
use crate::app::jwt::{JwtConfig, JwtService, TokenManager};
use crate::app::middleware::request_response_logger;
use crate::app::oauthold::{GoogleOAuthProvider, OAuthManager};
use crate::app::password::{Argon2Hasher, Hasher};
use crate::app::router;
use crate::app::state::AppState;
use crate::app::storage::StorageService;

#[cfg(feature = "storage-local")]
use crate::app::storage::local::LocalStorageService;

use crate::app::uid::{Generator, Snowflake};
use crate::auth::{
    inbound::state::AuthState,
    outbound::{
        orm::AuthORM,
        repository::AuthRepository,
        session::{SessionRedis, SessionRepository},
    },
    usecase::{
        authn::{AuthnService, AuthnUseCase},
        authz::{AuthzService, AuthzUseCase},
        profile::{ProfileService, ProfileUseCase},
    },
};
use axum::middleware;
use base64::{Engine as _, engine::general_purpose};
use bb8_redis::RedisConnectionManager;
use sea_orm::{ConnectOptions, Database};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::broadcast;
use tower::ServiceBuilder;
use tower_cookies::{CookieManagerLayer, Key};
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    decompression::RequestDecompressionLayer,
    timeout::TimeoutLayer,
};

mod app;
mod auth;
mod orm;

/// Initializes all dependencies and starts the web server.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Create a broadcast channel to signal shutdown to all application components.
    // Spawn a task to listen for shutdown signals (Ctrl+C and SIGTERM).
    let (shutdown_tx, _) = broadcast::channel(1);
    spawn_shutdown_listener(shutdown_tx.clone());

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
    let rds_pool = bb8::Pool::builder()
        .max_size(config.get::<u32>("database.max_connections")?)
        .build(rds_manager)
        .await?;

    // Initialize the Snowflake ID generator.
    let snowflake: Arc<dyn Generator> = Arc::new(
        Snowflake::builder(config.get("snowflake.worker_id")?)
            .with_epoch(1753981200000) // 2025-08-01 00:00:00 +07:00
            .build()?,
    );

    // Initialize the Argon2id hasher.
    let hasher: Arc<dyn Hasher> = Arc::new(Argon2Hasher::new());

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
    let storage_service: Arc<dyn StorageService> = {
        #[cfg(feature = "storage-local")]
        {
            let base_path = config.get("storage.local.base_path")?;
            let base_url = config.get("storage.local.base_url")?;
            Arc::new(LocalStorageService::new(base_path, base_url))
        }
        #[cfg(not(any(feature = "storage-local", feature = "storage-aws", feature = "storage-gcp")))]
        {
            panic!("No storage feature enabled. Please enable one, e.g., 'storage-local'.");
        }
    };

    // Initialize auth module
    let session_repo: Arc<dyn SessionRepository> = Arc::new(SessionRedis::new(rds_pool));
    let auth_repo: Arc<dyn AuthRepository> = Arc::new(AuthORM::new(db_pool.clone(), snowflake.clone()));
    let authn_svc: Arc<dyn AuthnUseCase> = Arc::new(AuthnService::new(
        config.clone(),
        hasher.clone(),
        snowflake.clone(),
        token_manager.clone(),
        session_repo,
        oauth_manager,
        auth_repo.clone(),
    ));
    let authz_svc: Arc<dyn AuthzUseCase> = Arc::new(AuthzService::new(auth_repo.clone()));
    let profile_svc: Arc<dyn ProfileUseCase> = Arc::new(ProfileService::new(
        Arc::clone(&config),
        snowflake,
        storage_service,
        hasher,
        auth_repo,
    ));

    // Assemble the final AppState from the shared resources and module states.
    let app_state = AppState {
        config: Arc::clone(&config),
        cookie_key,
        token: token_manager,
        auth: AuthState::new(authn_svc, authz_svc, profile_svc),
    };

    // Create the Router and Middlewares
    let timeout_secs = Duration::from_secs(app_state.config.get::<u64>("server.timeout_secs")?);
    let app = router::create_router_app(app_state.clone()).layer(
        ServiceBuilder::new()
            .layer(middleware::from_fn(request_response_logger))
            .layer(CookieManagerLayer::new())
            .layer(CorsLayer::new().allow_origin(Any)) // Enables CORS for all origins
            .layer(RequestDecompressionLayer::new()) // Enables request compression
            .layer(CompressionLayer::new()) // Enables response compression
            .layer(TimeoutLayer::new(timeout_secs)), // Adds a request timeout
    );

    let server_address = app_state.config.get::<String>("server.address")?;
    let listener = tokio::net::TcpListener::bind(&server_address).await?;

    tracing::info!("🚀 listening on {}", listener.local_addr()?);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_tx.subscribe().recv().await.ok();
            tracing::info!("🛑 Server is shutting down gracefully...");
        })
        .await?;

    // close / drop all holding resources
    Arc::try_unwrap(db_pool)
        .map_err(|_| "Failed to close database - references still exist")?
        .close()
        .await?;

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
