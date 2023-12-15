use anyhow::Result;

pub fn setup_tracing() -> Result<()> {
    use tracing_subscriber::{fmt, fmt::time::ChronoLocal, filter::{EnvFilter, LevelFilter}};

    let timer = {
        let format = "[%Y-%m-%d %H:%M:%S%.3f %:z]".to_string();
        ChronoLocal::new(format)
    };

    let filter = EnvFilter::from_default_env()
        .add_directive(LevelFilter::INFO.into());

    let subscriber = fmt()
        .compact()
        .with_timer(timer)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(false)
        .with_env_filter(filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}