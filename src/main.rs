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
}

#[derive(clap::Subcommand, Debug)]
enum RecordType {
    Cpu,
    Syscall { name: String },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.subcmd {
        Command::Record(record) => {
            let event = match record.record_type {
                RecordType::Cpu => RbperfEvent::Cpu,
                RecordType::Syscall { name } => RbperfEvent::Syscall(name),
            };
            let options = RbperfOptions { event: event };
            let mut r = Rbperf::new(options);
            r.add_pid(record.pid)?;

            let duration = std::time::Duration::from_secs(record.duration.unwrap_or(1));
            let mut profile = Profile::new();
            let sample_period = 99999;
            r.start(sample_period, duration, &mut profile)?;
            let folded = profile.folded();

            println!("{}", folded);

            let mut options = flamegraph::Options::default();
            let data = folded.as_bytes();
            let f = File::create("flame.html").unwrap();
            flamegraph::from_reader(&mut options, data, f).unwrap();

            let serialized = serde_json::to_string(&profile).unwrap();
            fs::write("rbperf_out.json", serialized).expect("Unable to write file");
        }
    }

    Ok(())
}
