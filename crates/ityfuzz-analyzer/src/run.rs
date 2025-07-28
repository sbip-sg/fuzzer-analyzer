use crate::types::RunArgs;
use crate::types::StatsEntry;
use csv::Writer;
use eyre::{Result, WrapErr, eyre};
use glob::glob;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use tracing::error;
use std::collections::HashMap;
use std::fs::{self};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::Mutex;
use tracing::debug;
use tracing::info;
use tracing::warn;

fn write_log_file(folder: &str, contract_id: &str, log_content: &str) -> Result<()> {
    let log_file_path = format!("raw-logs/{}/{}.log", folder, contract_id);
    // make parent folder if it does not exist
    let parent_dir = Path::new(&log_file_path).parent().unwrap();
    fs::create_dir_all(parent_dir).wrap_err_with(|| {
        format!(
            "Failed to create parent directory for log file: {}",
            parent_dir.display()
        )
    })?;
    fs::write(&log_file_path, log_content)?;
    Ok(())
}

pub fn handle_run_command(args: RunArgs) -> Result<()> {
    fs::create_dir_all(&args.output_dir).wrap_err_with(|| {
        format!(
            "Failed to create output directory: {}",
            args.output_dir.display()
        )
    })?;


    let all_contract_stats: Arc<Mutex<HashMap<String, Vec<StatsEntry>>>> = Arc::new(Mutex::new(HashMap::new()));

    let benchmark_glob_pattern = format!("{}/*", args.benchmark_base_dir.to_string_lossy());

    let glob_pattern_results = glob(&benchmark_glob_pattern)
        .wrap_err_with(|| format!("Invalid glob pattern: '{}'", benchmark_glob_pattern))?;

    let mut contract_dirs: Vec<PathBuf> = Vec::new();
    for entry_result in glob_pattern_results {
        let path = entry_result.wrap_err("Error processing a path from glob pattern")?;
        if path.is_dir() {
            contract_dirs.push(path);
        }
    }

    if contract_dirs.is_empty() {
        return Err(eyre!(
            "No contract directories found in {} matching pattern {}/* (looking for names starting with '20')",
            args.benchmark_base_dir.display(),
            args.benchmark_base_dir.display()
        ));
    }

    info!("Found {} contract directories", contract_dirs.len());

    let pb = ProgressBar::new(contract_dirs.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})\n{msg}",
        )
        .unwrap()
        .progress_chars("█▓▒░ "),
    );
    pb.set_message("Starting fuzzing...");

    let num_threads = args.jobs;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .wrap_err("Failed to create thread pool")?;

    pool.scope(|s| {
        for contract_dir_path in contract_dirs {
            let pb = pb.clone();
            let all_contract_stats = Arc::clone(&all_contract_stats);
            let args = &args;

            s.spawn(move |_| {
                pb.inc(1);
                let contract_id = contract_dir_path
                    .file_name()
                    .expect("Contract directory should have a name")
                    .to_string_lossy()
                    .into_owned();

                pb.set_message(format!("Fuzzing contract: {}", contract_id));

                let contract_files_glob = format!("{}/*", contract_dir_path.to_string_lossy());
                
                // Parse fuzzer options from string
                let mut options: Vec<String> = args.fuzzer_options
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();

                options.push("-t".to_string());
                options.push(contract_files_glob);
                
                if args.use_work_dir {
                    let now = chrono::Utc::now().format("%Y-%m-%d_%H-%M-%S").to_string();
                    let work_dir = format!(".work-dirs/{}/{}", now, contract_id);
                    options.push("-w".to_string());
                    options.push(work_dir);
                }

                match run_program_with_timeout(&args.fuzzer_path, &options, args.fuzz_timeout_seconds) {
                    Ok(log_content) => {
                        let folder = args.benchmark_base_dir.canonicalize().unwrap();
                        let folder = folder.file_name().unwrap_or_default().to_string_lossy();
                        if let Err(e) = write_log_file(&folder, &contract_id , &log_content){
                            error!(
                                "Failed to write log file for contract {}: {:?}",
                                contract_id, e
                            );
                        }
                        if log_content.trim().is_empty() {
                            info!(
                                "No output from fuzzer for {}, skipping parsing (likely timeout or crash before output).",
                                contract_id
                            );
                            return;
                        }
                        match parse_log(&log_content, &contract_id) {
                            Ok(entries) => {
                                if entries.is_empty() {
                                    warn!(
                                        "No statistical entries parsed for {}, though log was not empty. Log content:\n'{}'",
                                        contract_id, log_content
                                    );
                                } else {
                                    info!(
                                        "Parsed {} entries for contract {}",
                                        entries.len(),
                                        contract_id
                                    );
                                    write_csv(&contract_id, &entries, &args.output_dir).expect("Failed to write CSV");
                                    info!(
                                        "CSV saved for {} to {}/{}.instructions.stats.csv",
                                        contract_id,
                                        args.output_dir.display(),
                                        contract_id
                                    );
                                    all_contract_stats.lock().unwrap().insert(contract_id.clone(), entries);
                                }
                            }
                            Err(e) => {
                                info!(
                                    "Error parsing log for contract {}: {:?}\nLog content:\n{}",
                                    contract_id, e, log_content
                                );
                            }
                        }
                    }
                    Err(e) => {
                        info!("Error running fuzzer for contract {}: {:?}", contract_id, e);
                    }
                }
            });
        }
    });

    if all_contract_stats.lock().unwrap().is_empty() {
        info!("No data collected from any contracts. Cannot generate aggregate plot.");
    } else {
        #[cfg(feature = "plotting")]
        crate::plot::aggregate_and_plot_data(&all_contract_stats.lock().unwrap(), &args.output_dir, None)?;
        #[cfg(not(feature = "plotting"))]
        info!("Plot generation skipped (plotting feature disabled). CSV data has been saved.");
    }

    pb.finish_with_message(format!(
        "Run command complete. Outputs are in the '{}' directory.",
        args.output_dir.display()
    ));
    Ok(())
}

fn run_program_with_timeout(
    program_path: &str,
    args: &[String],
    timeout_seconds: u64,
) -> Result<String> {
    info!(
        "Running program {} with args {:?} and timeout {}s",
        program_path, args, timeout_seconds
    );

    let timeout_str = timeout_seconds.to_string();

    let child = Command::new("timeout")
        .args([&timeout_str, program_path])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()) // Capture stderr
        .spawn()
        .wrap_err_with(|| format!("Failed to start program {}", program_path))?;

    let output = child.wait_with_output()?;
    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        if !stderr_str.is_empty() {
            error!(
                "Stderr from running {} {:?}:\n{}",
                program_path,
                &args,
                stderr_str.trim()
            );
        }
        if output.status.code() == Some(124) {
            info!("Program {} {:?} timed out.", program_path, &args);
        } else {
            info!(
                "Program {} {:?} exited with status {}.",
                program_path, &args, output.status
            );
        }
    }

    let output = stdout_str + &stderr_str;

    Ok(output)
}

fn parse_log(log_content: &str, contract_id: &str) -> Result<Vec<StatsEntry>> {
    let mut entries = Vec::new();
    // parse start time from
    // INFO Ityfuzz start at 1749625856722
    let start_re =
        Regex::new(r".*Ityfuzz start at (\d+)").wrap_err("Failed to compile 'start at' regex")?;
    // parse coverage data
    // ^[[32m INFO^[[0m Coverage stat: time-millis: 1749628484080 instructions: 957/2248 branches: 49/112
    let coverage_re = Regex::new(
        r".*Coverage stat: time-millis: (?P<timestamp>\d+) instructions: (?P<instructions_covered>\d+)/(?P<total_instructions>\d+) branches: (?P<branches_covered>\d+)/\d+",
    )
    .wrap_err("Failed to compile 'coverage stat' regex")?;

    let mut began_at_millis: Option<u64> = None;

    for line in log_content.lines() {
        if began_at_millis.is_none() {
            if let Some(caps) = start_re.captures(line) {
                debug!(
                    "Found 'start at' timestamp in log for {}: {}",
                    contract_id, &caps[1]
                );
                began_at_millis = Some(caps[1].parse::<u64>().wrap_err_with(|| {
                    format!("Failed to parse 'start at' timestamp: {}", &caps[1])
                })?);
            }
        }

        if let Some(current_began_at) = began_at_millis {
            if let Some(caps) = coverage_re.captures(line) {
                let instructions_covered = caps["instructions_covered"].parse::<u64>().wrap_err_with(|| {
                    format!("Failed to parse instructions_covered: {}", &caps["instructions_covered"])
                })?;
                let branches_covered = caps["branches_covered"]
                    .parse::<u64>()
                    .wrap_err_with(|| format!("Failed to parse branches_covered: {}", &caps["branches_covered"]))?;
                let timestamp_millis: u64 = caps["timestamp"]
                    .parse::<u64>()
                    .wrap_err_with(|| format!("Failed to parse timestamp_millis: {}", &caps["timestamp"]))?;

                let total_instructions = caps["total_instructions"].parse::<u64>().wrap_err_with(|| {
                    format!("Failed to parse total_instructions: {}", &caps["total_instructions"])
                })?;

                if timestamp_millis >= current_began_at {
                    let time_taken_millis = timestamp_millis - current_began_at;
                    entries.push(StatsEntry {
                        instructions_covered,
                        branches_covered,
                        total_instructions,
                        time_taken_millis,
                    });
                } else {
                    return Err(eyre!(
                        "Timestamp {} is before the 'start at' timestamp {} for contract {}",
                        timestamp_millis,
                        current_began_at,
                        contract_id
                    ));
                }
            }
        }
    }

    if began_at_millis.is_none() && !log_content.trim().is_empty() {
        warn!(
            "No 'start' timestamp found in log for {}, and no stat lines. Log: '{}'",
            contract_id,
            log_content.chars().take(300).collect::<String>()
        );
        return Err(eyre!(
            "No 'start at' timestamp found in log for {} despite other stat lines being present.",
            contract_id
        ));
    }

    entries.sort_by_key(|e| e.time_taken_millis);
    entries.dedup_by_key(|e| e.time_taken_millis);

    Ok(entries)
}

fn write_csv(contract_id: &str, entries: &[StatsEntry], output_path_base: &Path) -> Result<()> {
    let csv_path = output_path_base.join(format!("{}.instructions.stats.csv", contract_id));
    let mut wtr = Writer::from_path(&csv_path)
        .wrap_err_with(|| format!("Failed to create CSV writer for {}", csv_path.display()))?;
    for entry in entries {
        wtr.serialize(entry)
            .wrap_err("Failed to serialize entry to CSV")?;
    }
    wtr.flush().wrap_err("Failed to flush CSV writer")?;
    Ok(())
}
