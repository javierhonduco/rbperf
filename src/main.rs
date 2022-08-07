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
    ringbuf: bool,
}

#[derive(clap::Subcommand, Debug, PartialEq)]
enum RecordType {
    Cpu,
    Syscall { names: Vec<String> },
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

            let event = match record.record_type {
                RecordType::Cpu => RbperfEvent::Cpu {
                    sample_period: 99999,
                },
                RecordType::Syscall { ref names } => RbperfEvent::Syscall(names.clone()),
            };
            let options = RbperfOptions {
                event,
                verbose_bpf_logging: record.verbose_bpf_logging,
                use_ringbuf: record.ringbuf,
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
                    RecordType::Syscall { names: _ } => {
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
