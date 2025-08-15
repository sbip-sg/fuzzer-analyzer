use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct CompileArgs {
    /// Path to the list file (e.g., B1.list)
    #[arg(
        long,
        value_name = "FILE",
        default_value = "release/benchmarks/assets/B1.list"
    )]
    pub list_file: PathBuf,

    /// Base directory containing .sol files to compile (e.g., release/benchmarks/B1/sol)
    #[arg(long, value_name = "DIR")]
    pub solc_input_dir: PathBuf,

    /// Base output directory for compiled contracts (e.g., b1 or output_b1)
    /// Each contract will get a subdirectory here: <solc_output_dir>/<contract_filename_base>/
    #[arg(long, value_name = "DIR" )]
    pub solc_output_dir: PathBuf,

    /// Timeout in seconds for solc compilation per contract
    #[arg(long, value_name = "SECONDS", default_value_t = 30)]
    pub solc_timeout_seconds: u64,

    /// Path to solc binary (defaults to 'solc' in PATH)
    #[arg(long, value_name = "PATH")]
    pub solc_binary: Option<PathBuf>,

    /// Generate PTX files for GPU execution (requires ptxsema, llvm tools)
    #[arg(long)]
    pub generate_ptx: bool,
}

#[derive(Parser, Debug)]
pub struct PTXArgs{
    /// Output directory of `compile` command. Folder structure should be:
    /// <solc_output_dir>/<contract_folder>/<main_contract_name>.bin
    #[arg(long, value_name = "DIR")]
    pub solc_output_dir: PathBuf,

}

#[derive(Parser, Debug)]
#[command(author, version, about = "Analyzes fuzzer output or plots existing data", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run the fuzzer, analyze output, write CSVs, and plot results
    Run(RunArgs),
    /// Plot results from existing CSV data in the output directory
    Plot(PlotArgs),
    /// Compile contracts from source code and optionally generate PTX files
    Compile(CompileArgs),
    /// Generate PTX files for compiled contracts
    PTX(PTXArgs),
}

#[derive(Parser, Debug)]
pub struct RunArgs {
    /// Path to the fuzzer executable
    #[arg(short, long, value_name = "FILE")]
    pub fuzzer_path: String,

    /// Additional arguments to be added after the fuzzer_path
    #[arg(long)]
    pub fuzzer_options: String,

    /// Base directory containing benchmark contract directories (e.g., b1)
    #[arg(short, long, value_name = "DIR")]
    pub benchmark_base_dir: PathBuf,

    /// Output directory for CSV files and the plot
    #[arg(short, long, value_name = "DIR", default_value = "analysis_output")]
    pub output_dir: PathBuf,

    /// Timeout in seconds for running the fuzzer on each contract
    #[arg(long, value_name = "SECONDS", default_value_t = 15)]
    pub fuzz_timeout_seconds: u64,

    /// Whether to use PTX files for GPU execution (requires pre-compiled kernel.ptx files in the output directory)
    #[arg(long)]
    pub use_ptx: bool,

    /// Abort the entire analysis run when encountering CUDA system errors
    #[arg(long, default_value_t = false)]
    pub abort_on_cuda_error: bool,
}

#[derive(Parser, Debug)]
pub struct PlotArgs {
    /// Directory containing the CSV data files and where the plot will be saved
    #[arg(short, long, value_name = "DIR", default_value = "analysis_output")]
    pub output_dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsEntry {
    pub instructions_covered: u64,
    pub branches_covered: u64,
    pub time_taken_nanos: u64,
}
