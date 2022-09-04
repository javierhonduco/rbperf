#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)] // TODO: remove this
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod arch;
pub mod binary;
pub mod bpf;
pub mod events;
pub mod info;
pub mod process;
pub mod profile;
pub mod rbperf;
pub mod ruby_readers;
pub mod ruby_versions;
