use inferno::flamegraph;
use rbperf::rbperf::Rbperf;
use std::fs;
use std::fs::File;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    pid: i32,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let sample_period = 99999;
    let duration = std::time::Duration::from_secs(10);

    let mut r = Rbperf::new();
    r.add_pid(args.pid)?;
    let profile = r.profile_cpu(sample_period, duration)?;
    let folded = profile.folded();

    println!("{}", folded);

    let mut options = flamegraph::Options::default();
    let data = folded.as_bytes();
    let f = File::create("flame.html").unwrap();
    flamegraph::from_reader(&mut options, data, f).unwrap();

    let serialized = serde_json::to_string(&profile).unwrap();
    fs::write("rbperf_out.json", serialized).expect("Unable to write file");

    Ok(())
}
