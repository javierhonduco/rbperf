use std::fmt;
use std::path::PathBuf;

use anyhow::anyhow;
use log::debug;
use thiserror::Error;

use crate::binary::{ruby_current_vm_address, ruby_version};
use proc_maps::{get_process_maps, Pid};

#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("process with pid {pid:?} is not running")]
    ProcessDoesNotExist { pid: Pid },
}

pub struct LibrubyInfo {
    pub executable: PathBuf,
    pub address: u64,
}

pub struct ProcessInfo {
    pub pid: Pid,
    pub ruby_version: String,
    pub ruby_vm_ptr_address: u64,
    pub process_base_address: u64,
    pub libruby: Option<LibrubyInfo>,
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "pid: {}", self.pid)?;
        match &self.libruby {
            Some(libruby) => {
                writeln!(
                    f,
                    "libruby: {} @ 0x{:x}",
                    libruby.executable.display(),
                    libruby.address
                )?;
            }
            None => {
                writeln!(f, "statically linked")?;
            }
        }
        writeln!(
            f,
            "ruby main thread address: 0x{:x}",
            self.ruby_main_thread_address()
        )?;
        writeln!(f, "process base address: 0x{:x}", self.process_base_address)?;
        writeln!(f, "ruby version: {:?}", self.ruby_version)?;

        Ok(())
    }
}

fn find_libruby(pid: Pid) -> Result<Option<LibrubyInfo>, ProcessError> {
    let maps = get_process_maps(pid).map_err(|_| ProcessError::ProcessDoesNotExist { pid })?;
    // https://github.com/rust-lang/rust/issues/62358
    for map in maps {
        if let Some(s) = map.filename() {
            if s.to_str().unwrap().contains("libruby") {
                return Ok(Some(LibrubyInfo {
                    executable: map.filename().unwrap().to_path_buf(),
                    address: map.start() as u64,
                }));
            }
        }
    }
    Ok(None)
}

impl ProcessInfo {
    pub fn new(pid: Pid) -> Result<Self, anyhow::Error> {
        let libruby = find_libruby(pid as Pid)?;

        let mut bin_path = PathBuf::new();
        bin_path.push("/proc/");
        bin_path.push(pid.to_string());

        if let Some(l) = &libruby {
            bin_path.push("root");
            bin_path.push(
                l.executable
                    .clone()
                    .strip_prefix("/")
                    .expect("remove prefix"),
            )
        } else {
            bin_path.push("exe");
        }

        let ruby_version = ruby_version(&bin_path).unwrap();

        debug!("Binary {:?}", bin_path);
        let symbol = ruby_current_vm_address(&bin_path, &ruby_version)?;

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
        match &self.libruby {
            Some(libruby) => libruby.address + self.ruby_vm_ptr_address,
            None => self.process_base_address + self.ruby_vm_ptr_address,
        }
    }
}
