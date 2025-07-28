use clap::Parser;
use eyre::Result;
use run::handle_run_command;
use std::env;
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;
use types::{Cli, Commands};

#[cfg(feature = "plotting")]
mod plot;
mod run;
mod types;

fn main() -> Result<()> {
    // Create log file
    let log_level = match env::var("LOG_LEVEL").unwrap_or_default().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let file_appender = tracing_appender::rolling::never(
        ".",
        format!(
            "ityfuzz-analyzer-{}.log",
            chrono::Utc::now().format("%Y-%m-%d_%H-%M-%S")
        ),
    );

    let (non_blocking_appender, _guard) = tracing_appender::non_blocking(file_appender);

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_file(true)
        .with_line_number(true)
        .with_writer(non_blocking_appender)
        .with_ansi(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Setting default tracing subscriber failed");

    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => {
            info!("Executing 'run' command...");
            handle_run_command(args)?;
        }
        Commands::Plot(args) => {
            #[cfg(feature = "plotting")]
            {
                info!("Executing 'plot' command...");
                plot::handle_plot_command(args)?;
            }
            #[cfg(not(feature = "plotting"))]
            {
                eprintln!("Plot functionality is disabled. Rebuild with plotting feature enabled.");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
