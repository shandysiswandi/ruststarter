//! The binary entry point for the application.

use ruststarter::run;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(
            fmt::layer()
                .json()
                .with_target(true) // Include the target (module path)
                .with_file(true) // Include file names
                .with_line_number(true) // Include line numbers
                .with_span_events(fmt::format::FmtSpan::CLOSE),
        )
        .init();

    if let Err(err) = run().await {
        eprintln!("❌ Application failed to start: {err}");
        std::process::exit(1);
    }
}
