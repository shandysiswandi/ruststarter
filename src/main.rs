//! The binary entry point for the application.

use ruststarter::run;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    if let Err(err) = run().await {
        eprintln!("❌ Application failed to start: {err}");
        std::process::exit(1);
    }
}
