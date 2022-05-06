use std::path::PathBuf;

use anyhow::{anyhow, Result};

use crate::binary::{ruby_current_thread_address, ruby_version};
use proc_maps::{get_process_maps, Pid};

pub struct ProcessInfo {
    pub pid: Pid,
    pub ruby_version: String,
    pub ruby_vm_ptr_address: u64,
    pub process_base_address: u64,
    pub libruby: Option<(u64, PathBuf)>,
}

fn find_libruby(pid: Pid) -> Option<(u64, PathBuf)> {
    let maps = get_process_maps(pid).unwrap();
    // https://github.com/rust-lang/rust/issues/62358
    for map in maps {
        if let Some(s) = map.filename() {
            if s.to_str()?.contains("libruby") {
                return Some((map.start() as u64, map.filename().unwrap().to_path_buf()));
            }
        }
    }
    None
}

impl ProcessInfo {
    pub fn new(pid: Pid) -> Result<Self> {
        let libruby = find_libruby(pid as Pid);

        let mut bin_path = PathBuf::new();
        bin_path.push("/proc/");
        bin_path.push(pid.to_string());
        bin_path.push("root");

        if let Some(l) = &libruby {
            bin_path.push(l.1.clone().strip_prefix("/").expect("remove prefix"))
        }

        println!("Binary {:?}", bin_path);
        let symbol = ruby_current_thread_address(&bin_path)?;

        let ruby_version = ruby_version(&bin_path)?;
        if &ruby_version[0..3] != "2.7" {
            panic!(
                "Only Ruby '2.7.*' is supported, '{}' was provided",
                ruby_version
            );
        }

        let maps = get_process_maps(pid as Pid)?;
        let base_address = maps
            .first()
            .ok_or_else(|| anyhow!("failure reading the first maps entry"))?
            .start() as u64;

        Ok(ProcessInfo {
            pid,
            ruby_version,
            ruby_vm_ptr_address: symbol.address,
            process_base_address: base_address,
            libruby,
        })
    }

    pub fn ruby_main_thread_address(&self) -> u64 {
        let (process_base_address, libruby_base_address) = match &self.libruby {
            Some(l) => (0, l.0),
            None => (self.process_base_address, 0),
        };
        process_base_address + libruby_base_address + self.ruby_vm_ptr_address
    }
}
