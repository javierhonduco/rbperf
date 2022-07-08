use chrono::DateTime;
use chrono::Utc;
use inferno::flamegraph;
use std::fs;
use std::fs::File;

use anyhow::Result;
use clap::Parser;

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
}

#[derive(clap::Subcommand, Debug)]
enum RecordType {
    Cpu,
    Syscall { name: String },
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    match args.subcmd {
        Command::Record(record) => {
            let event = match record.record_type {
                RecordType::Cpu => RbperfEvent::Cpu {
                    sample_period: 99999,
                },
                RecordType::Syscall { name } => RbperfEvent::Syscall(name),
            };
            let options = RbperfOptions {
                event,
                verbose_bpf_logging: record.verbose_bpf_logging,
            };

            let mut r = Rbperf::new(options);
            r.add_pid(record.pid)?;

            let duration = std::time::Duration::from_secs(record.duration.unwrap_or(1));
            let mut profile = Profile::new();
            r.start(duration, &mut profile)?;
            let folded = profile.folded();

            let mut options = flamegraph::Options::default();
            let data = folded.as_bytes();
            let now: DateTime<Utc> = Utc::now();
            let name_suffix = now.format("%m%d%Y_%Hh%Mm%Ss");

            let f = File::create(format!("rbperf_flame_{}.svg", name_suffix)).unwrap();
            flamegraph::from_reader(&mut options, data, f).unwrap();

            let serialized = serde_json::to_string(&profile).unwrap();
            fs::write(format!("rbperf_out_{}.json", name_suffix), serialized)
                .expect("Unable to write file");
        }
    }

    Ok(())
}
