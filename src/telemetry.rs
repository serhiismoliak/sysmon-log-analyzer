use std::sync::LazyLock;
use tracing_subscriber::{EnvFilter, fmt};
use tracing::Level;

static TRACING_INIT: LazyLock<()> = LazyLock::new(||{
    fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive(Level::INFO.into()),
        )
        .with_writer(std::io::stderr)
        .init()
});

pub fn init_tracing() {
    LazyLock::force(&TRACING_INIT);
}