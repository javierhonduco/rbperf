use chrono::DateTime;
use chrono::Utc;
use clap::Parser;
use core::sync::atomic::{AtomicBool, Ordering};
use inferno::flamegraph;
use nix::unistd::Uid;
use std::fs;
use std::fs::File;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use rbperf::profile::Profile;
use rbperf::rbperf::{Rbperf, RbperfEvent, RbperfOptions};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    subcmd: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    Record(RecordSubcommand),
}

#[derive(Parser, Debug)]
struct RecordSubcommand {
    #[clap(short, long)]
    pid: i32,
    #[clap(short, long)]
    duration: Option<u64>,
    #[clap(subcommand)]
    record_type: RecordType,
    #[clap(long)]
    verbose_bpf_logging: bool,
    #[clap(long)]
    verbose_libbpf_logging: bool,
    #[clap(long)]
    ringbuf: bool,
}

#[derive(clap::Subcommand, Debug, PartialEq)]
enum RecordType {
    Cpu,
    Syscall(SycallSubcommand),
}

#[derive(Parser, Debug, PartialEq)]
struct SycallSubcommand {
    names: Vec<String>,
    #[clap(short, long)]
    list: bool,
}

fn available_syscalls() -> Vec<String> {
    let mut syscalls = Vec::new();

    let paths = fs::read_dir("/sys/kernel/debug/tracing/events/syscalls/").unwrap();

    for direntry in paths {
        let path = direntry.unwrap().path();
        let filename = path.file_name().unwrap().to_string_lossy();
        if filename.contains("sys_") {
            syscalls.push(filename.strip_prefix("sys_").unwrap().to_string());
        }
    }

    syscalls
}
fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    match args.subcmd {
        Command::Record(record) => {
            if !Uid::current().is_root() {
                return Err(anyhow!("rbperf requires root to load and run BPF programs"));
            }

            if let RecordType::Syscall(ref syscall_subcommand) = record.record_type {
                if syscall_subcommand.list {
                    println!("Available syscalls:");
                    println!();

                    for syscall in available_syscalls() {
                        println!("{}", syscall);
                    }
                    return Ok(());
                }

                if syscall_subcommand.names.is_empty() {
                    return Err(anyhow!("No syscall names were provided. With rbperf record syscall --list you can see the available system calls."));
                }
            };

            let event = match record.record_type {
                RecordType::Cpu => RbperfEvent::Cpu {
                    sample_period: 99999,
                },
                RecordType::Syscall(ref syscall_subcommand) => {
                    RbperfEvent::Syscall(syscall_subcommand.names.clone())
                }
            };
            let options = RbperfOptions {
                event,
                verbose_bpf_logging: record.verbose_bpf_logging,
                use_ringbuf: record.ringbuf,
                verbose_libbpf_logging: record.verbose_libbpf_logging,
            };

            let mut r = Rbperf::new(options);
            r.add_pid(record.pid)?;

            let duration = std::time::Duration::from_secs(record.duration.unwrap_or(1));
            let mut profile = Profile::new();
            let stats = r.start(duration, &mut profile, runnable)?;
            let folded = profile.folded();

            if stats.total_events == 0 {
                match record.record_type {
                    RecordType::Cpu => {
                        return Err(anyhow!("No stacks were collected. This might mean that this process is mostly IO bound. If you believe that this might be a bug, please open an issue at https://github.com/javierhonduco/rbperf. Thanks!"));
                    }
                    RecordType::Syscall(_) => {
                        return Err(anyhow!("No stacks were collected. Perhaps this syscall is never called. If you believe that this might be a bug, please open an issue at https://github.com/javierhonduco/rbperf. Thanks!"));
                    }
                }
            }

            let mut options = flamegraph::Options::default();
            let data = folded.as_bytes();
            let now: DateTime<Utc> = Utc::now();
            let name_suffix = now.format("%m%d%Y_%Hh%Mm%Ss");

            let flame_path = format!("rbperf_flame_{}.svg", name_suffix);
            let f = File::create(&flame_path).unwrap();
            flamegraph::from_reader(&mut options, data, f).unwrap();

            let serialized = serde_json::to_string(&profile).unwrap();
            fs::write(format!("rbperf_out_{}.json", name_suffix), serialized)
                .expect("Unable to write file");

            println!(
                "Got {} samples and {} errors",
                stats.total_events,
                stats.total_errors()
            );
            println!("Flamegraph written to: {}", flame_path);
        }
    }

    Ok(())
}
