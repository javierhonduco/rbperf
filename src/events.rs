use std::fs;
use std::os::raw::{c_int, c_ulong};

use anyhow::{anyhow, Result};
use errno::errno;
use libc::{self, pid_t};
use log::debug;

use perf_event_open_sys as sys;
use perf_event_open_sys::bindings::{perf_event_attr, PERF_FLAG_FD_CLOEXEC};

// This crate bindings have been generated in a x86 machine, including
// the syscall number. Turns out different architectures have different
// syscall numbers. Will open an issue upstream, but meanwhile, let's
// hardcode the syscall number for arm64
#[cfg(any(target_arch = "arm64", target_arch = "aarch64"))]
unsafe fn perf_event_open(
    attrs: *mut perf_event_attr,
    pid: pid_t,
    cpu: c_int,
    group_fd: c_int,
    flags: c_ulong,
) -> c_int {
    libc::syscall(241u32 as libc::c_long, attrs, pid, cpu, group_fd, flags) as c_int
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn perf_event_open(
    attrs: *mut perf_event_attr,
    pid: pid_t,
    cpu: c_int,
    group_fd: c_int,
    flags: c_ulong,
) -> c_int {
    sys::perf_event_open(attrs, pid, cpu, group_fd, flags) as c_int
}

pub unsafe fn setup_perf_event(cpu: i32, sample_period: u64) -> Result<c_int> {
    let mut attrs = sys::bindings::perf_event_attr::default();

    attrs.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;
    attrs.type_ = sys::bindings::perf_type_id_PERF_TYPE_SOFTWARE;
    attrs.config = sys::bindings::perf_sw_ids_PERF_COUNT_SW_CPU_CLOCK as u64;
    attrs.__bindgen_anon_1.sample_period = sample_period;
    attrs.set_disabled(1);

    let fd = perf_event_open(
        &mut attrs,
        -1,                          /* pid */
        cpu,                         /* cpu */
        -1,                          /* group_fd */
        PERF_FLAG_FD_CLOEXEC as u64, /* flags */
    );

    if fd < 0 {
        return Err(anyhow!("setup_perf_event failed with errno {}", errno()));
    }

    Ok(fd)
}

pub unsafe fn setup_syscall_event(syscall: &str) -> Result<c_int> {
    let mut attrs = sys::bindings::perf_event_attr::default();

    attrs.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;
    attrs.type_ = sys::bindings::perf_type_id_PERF_TYPE_TRACEPOINT;

    let path = format!(
        "/sys/kernel/debug/tracing/events/syscalls/sys_{}/id",
        syscall
    );
    let mut id = fs::read_to_string(&path)?;
    id.pop(); // Remove newline
    debug!("syscall with id {} found in {}", id, &path);

    attrs.config = id.parse::<u64>()?;
    // attrs.__bindgen_anon_1.sample_period = sample_period;
    // attr.wakeup_events = 1;
    attrs.set_disabled(1);

    let fd = perf_event_open(
        &mut attrs,
        -1,                          /* pid */
        0,                           /* cpu */
        -1,                          /* group_fd */
        PERF_FLAG_FD_CLOEXEC as u64, /* flags */
    );

    if fd < 0 {
        return Err(anyhow!("setup_perf_event failed with errno {}", errno()));
    }

    Ok(fd)
}
