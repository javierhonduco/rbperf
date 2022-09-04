use crate::bpf::features::FeaturesSkelBuilder;
use anyhow::{anyhow, Result};
use nix::sys::utsname::uname;
use std::fs::File;
use std::thread;
use std::time::Duration;

pub struct SystemInfo {
    pub os_release: String,
    pub debug_fs: bool,
}

pub struct BpfFeatures {
    pub is_jited: bool,
    pub has_stats: bool,
    pub has_tail_call: bool,
    pub has_ringbuf: bool,
    pub has_bpf_loop: bool,
}

pub struct Info {
    pub system: SystemInfo,
    pub bpf: Result<BpfFeatures>,
}

pub fn info() -> Result<Info> {
    let skel_builder = FeaturesSkelBuilder::default();
    let open_skel = skel_builder.open().unwrap();
    let mut bpf = open_skel.load().unwrap();
    bpf.attach().unwrap();

    thread::sleep(Duration::from_millis(50));

    let bpf_features = if bpf.bss().feature_has_run {
        Ok(BpfFeatures {
            is_jited: bpf.bss().feature_is_jited,
            has_stats: bpf.bss().feature_has_stats,
            has_tail_call: bpf.bss().feature_has_tail_call,
            has_ringbuf: bpf.bss().feature_has_ringbuf,
            has_bpf_loop: bpf.bss().feature_bpf_loop,
        })
    } else {
        Err(anyhow!("Could not find out supported BPF features"))
    };

    Ok(Info {
        system: SystemInfo {
            os_release: uname().release().to_string(),
            debug_fs: File::open("/sys/kernel/debug/").is_ok(),
        },
        bpf: bpf_features,
    })
}
