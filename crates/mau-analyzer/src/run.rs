use crate::plot::aggregate_and_plot_data;
use crate::types::RunArgs;
use crate::types::StatsEntry;
use csv::Writer;
use eyre::{Result, WrapErr, eyre};
use glob::glob;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use std::collections::HashMap;
use std::fs::{self};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tracing::error;
use tracing::info;

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

    let mut all_contract_stats: HashMap<String, Vec<StatsEntry>> = HashMap::new();

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

    for contract_dir_path in contract_dirs {
        pb.inc(1);
        let contract_id = contract_dir_path
            .file_name()
            .ok_or_else(|| eyre!("Could not get file name from path: {:?}", contract_dir_path))?
            .to_string_lossy()
            .into_owned();

        pb.set_message(format!("Fuzzing contract: {}", contract_id));

        let contract_files_glob = format!("{}/*", contract_dir_path.to_string_lossy());
        let mut options = vec![];
        for option in args.fuzzer_options.split_whitespace() {
            options.push(option);
        }

        let ptx_path = contract_dir_path.join("kernel.ptx");
        let ptx_path_str = ptx_path.to_string_lossy().to_string();
        if args.use_ptx {
            match ptx_path.try_exists() {
                Ok(true) => {
                    options.push("--ptx-path");
                    options.push(&ptx_path_str);
                    options.push("--gpu-dev");
                    options.push("0");
                }
                _ => {
                    error!(
                        "PTX file not found for contract {} at {}, skipping contract at {}",
                        contract_id,
                        ptx_path_str,
                        contract_dir_path.display()
                    );
                }
            }
        }

        options.append(&mut vec!["-t", &contract_files_glob]);

        match run_program_with_timeout(&args.fuzzer_path, &options[..], args.fuzz_timeout_seconds) {
            Ok(log_content) => {
                let folder = args.benchmark_base_dir.canonicalize().unwrap();
                let folder = folder.file_name().unwrap_or_default().to_string_lossy();
                if let Err(e) = write_log_file(&folder, &contract_id , &log_content){
                    error!(
                        "Failed to write log file for contract {}: {:?}",
                        contract_id, e
                    );
                }

                // Check for CUDA system errors
                if log_content.contains("SYSTEM ERROR : [Cuda]") {
                    if args.abort_on_cuda_error {
                        error!(
                            "CUDA system error detected for contract {}. Aborting entire analysis run. Check the log file at raw-logs/{}/{}.log",
                            contract_id, folder, contract_id
                        );
                        return Err(eyre!(
                            "CUDA system error detected in contract {}. Analysis aborted.",
                            contract_id
                        ));
                    } else {
                        error!(
                            "CUDA system error detected for contract {}. Skipping this contract. Check the log file at raw-logs/{}/{}.log",
                            contract_id, folder, contract_id
                        );
                        continue;
                    }
                }

                if log_content.trim().is_empty() {
                    info!(
                        "No output from fuzzer for {}, skipping parsing (likely timeout or crash before output).",
                        contract_id
                    );
                    continue;
                }
                match parse_log(&log_content, &contract_id) {
                    Ok(entries) => {
                        if entries.is_empty() {
                            if !log_content.trim().is_empty() {
                                // Only print if log was not empty
                                info!(
                                    "No statistical entries parsed for {}, though log was not empty. Log (first 100 chars): '{}'",
                                    contract_id,
                                    log_content.chars().take(100).collect::<String>()
                                );
                            } else {
                                info!(
                                    "No statistical entries parsed for {} (empty log).",
                                    contract_id
                                );
                            }
                        } else {
                            info!(
                                "Parsed {} entries for contract {}",
                                entries.len(),
                                contract_id
                            );
                            write_csv(&contract_id, &entries, &args.output_dir)?;
                            info!(
                                "CSV saved for {} to {}/{}.instructions.stats.csv",
                                contract_id,
                                args.output_dir.display(),
                                contract_id
                            );
                            all_contract_stats.insert(contract_id.clone(), entries);
                        }
                    }
                    Err(e) => {
                        info!(
                            "Error parsing log for contract {}: {:?}\nLog content (first 200 chars):\n{}",
                            contract_id,
                            e,
                            log_content.chars().take(200).collect::<String>()
                        );
                    }
                }
            }
            Err(e) => {
                info!("Error running fuzzer for contract {}: {:?}", contract_id, e);
            }
        }
    }

    if all_contract_stats.is_empty() {
        info!("No data collected from any contracts. Cannot generate aggregate plot.");
    } else {
        aggregate_and_plot_data(&all_contract_stats, &args.output_dir, None)?;
    }

    pb.finish_with_message(format!(
        "Run command complete. Outputs are in the '{}' directory.",
        args.output_dir.display()
    ));
    Ok(())
}

fn run_program_with_timeout(
    program_path: &str,
    args: &[&str],
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
            info!(
                "Stderr from running {}:\n{}",
                program_path,
                stderr_str.trim()
            );
        }
        if output.status.code() == Some(124) {
            info!("Program {} timed out.", program_path);
            // For timeout, we still want to process any stdout produced, so we don't return Err here.
        } else {
            info!(
                "Program {} (or timeout command) exited with status {}.",
                program_path, output.status
            );
        }
    }


    let output= stdout_str + &stderr_str;

    Ok(output)
}

fn parse_log(log_content: &str, contract_id: &str) -> Result<Vec<StatsEntry>> {
    let mut entries = Vec::new();
    let began_at_re =
        Regex::new(r"Began at (\d+)").wrap_err("Failed to compile 'Began at' regex")?;
    let stats_re =
        Regex::new(r"Instruction Covered: (\d+); Branch Covered: (\d+) Timestamp Nanos: (\d+)")
            .wrap_err("Failed to compile 'Stats' regex")?;

    let mut began_at_nanos: Option<u64> = None;

    for line in log_content.lines() {
        if began_at_nanos.is_none() {
            if let Some(caps) = began_at_re.captures(line) {
                began_at_nanos = Some(caps[1].parse::<u64>().wrap_err_with(|| {
                    format!("Failed to parse 'Began at' timestamp: {}", &caps[1])
                })?);
            }
        }

        if let Some(current_began_at) = began_at_nanos {
            if let Some(caps) = stats_re.captures(line) {
                let instructions_covered = caps[1].parse::<u64>().wrap_err_with(|| {
                    format!("Failed to parse instructions_covered: {}", &caps[1])
                })?;
                let branches_covered = caps[2]
                    .parse::<u64>()
                    .wrap_err_with(|| format!("Failed to parse branches_covered: {}", &caps[2]))?;
                let timestamp_nanos: u64 = caps[3]
                    .parse::<u64>()
                    .wrap_err_with(|| format!("Failed to parse timestamp_nanos: {}", &caps[3]))?;

                if timestamp_nanos >= current_began_at {
                    let time_taken_nanos = timestamp_nanos - current_began_at;
                    entries.push(StatsEntry {
                        instructions_covered,
                        branches_covered,
                        time_taken_nanos,
                    });
                }
            }
        }
    }

    if began_at_nanos.is_none() && !log_content.trim().is_empty() {
        // Check if log_content is not empty before erroring for missing "Began at"
        let non_empty_meaningful_lines = log_content.lines().any(|l| stats_re.is_match(l));
        if non_empty_meaningful_lines {
            return Err(eyre!(
                "No 'Began at' timestamp found in log for {} despite other stat lines being present.",
                contract_id
            ));
        } else if !log_content.trim().is_empty() {
            info!(
                "Warning: No 'Began at' timestamp found in log for {}, and no stat lines. Log: '{}'",
                contract_id,
                log_content.chars().take(100).collect::<String>()
            ); // Print only first 100 chars
        }
    }

    entries.sort_by_key(|e| e.time_taken_nanos);
    entries.dedup_by_key(|e| e.time_taken_nanos);

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
