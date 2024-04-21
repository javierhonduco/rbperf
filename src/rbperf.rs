use core::sync::atomic::{AtomicBool, Ordering};
use libbpf_rs::{MapFlags, MapType, PerfBufferBuilder, ProgramType};
use serde_yaml;
use std::collections::HashMap;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use anyhow::Result;
use log::{debug, error, info};
use proc_maps::Pid;
use syscalls;

use crate::arch;
use crate::bpf::rbperf::{rbperf_rodata_types::rbperf_event_type, RbperfSkel, RbperfSkelBuilder};
use crate::events::{setup_perf_event, setup_syscall_event};
use crate::process::ProcessInfo;
use crate::profile::Profile;
use crate::ruby_readers::{any_as_u8_slice, parse_frame, parse_stack, str_from_u8_nul};
use crate::ruby_versions::ruby_version_configs_yaml;
use crate::RubyVersionOffsets;
use crate::{
    ruby_stack_status_STACK_INCOMPLETE, ProcessData, RubyStack, RBPERF_STACK_READING_PROGRAM_IDX,
};

use num_cpus;

#[derive(Clone)]
pub enum RbperfEvent {
    Cpu { sample_freq: u64 },
    Syscall(Vec<String>),
}

impl From<RbperfEvent> for rbperf_event_type {
    fn from(event: RbperfEvent) -> rbperf_event_type {
        match event {
            RbperfEvent::Cpu { sample_freq: _ } => rbperf_event_type::RBPERF_EVENT_ON_CPU_SAMPLING,
            RbperfEvent::Syscall(_) => rbperf_event_type::RBPERF_EVENT_SYSCALL,
        }
    }
}

pub struct Rbperf<'a> {
    bpf: RbperfSkel<'a>,
    duration: std::time::Duration,
    started_at: Option<Instant>,
    sender: Arc<Mutex<std::sync::mpsc::Sender<RubyStack>>>,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<RubyStack>>>,
    supported_ruby_versions: HashMap<RubyVersion, u32>,
    event: RbperfEvent,
    use_ringbuf: bool,
    enable_linenos: bool,
    pub stats: Stats,
}

#[derive(Default, Clone, Debug)]
pub struct Stats {
    pub total_events: u32,
    // Events discarded due to the kernel buffer being full.
    pub lost_event_errors: u32,
    // Failed to retrieve sample due to a failed read from a map.
    pub map_reading_errors: u32,
    // The stack is not complete.
    pub truncated_stacks: u32,
    // How many times have we bumped into garbled data.
    pub garbled_data_errors: u32,
}

impl Stats {
    pub fn total_errors(&self) -> u32 {
        self.lost_event_errors
            + self.map_reading_errors
            + self.truncated_stacks
            + self.garbled_data_errors
    }

    pub fn stack_errors(&self) -> u32 {
        self.map_reading_errors + self.truncated_stacks + self.garbled_data_errors
    }
}

pub struct RbperfOptions {
    pub event: RbperfEvent,
    pub verbose_bpf_logging: bool,
    pub use_ringbuf: bool,
    pub verbose_libbpf_logging: bool,
    pub disable_pid_race_detector: bool,
    pub enable_linenos: bool,
}

fn handle_event(
    sender: &mut Arc<Mutex<std::sync::mpsc::Sender<RubyStack>>>,
    _cpu: i32,
    data: &[u8],
) {
    let tx = sender.clone();
    let stack = unsafe { parse_stack(data) };
    tx.lock().unwrap().send(stack).unwrap();
}

fn handle_lost_events(cpu: i32, count: u64) {
    error!("Lost {} events on CPU {}", count, cpu);
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct RubyVersion {
    major_version: i32,
    minor_version: i32,
    patch_version: i32,
}

impl RubyVersion {
    pub fn new(major_version: i32, minor_version: i32, patch_version: i32) -> Self {
        Self {
            major_version,
            minor_version,
            patch_version,
        }
    }
}

impl<'a> Rbperf<'a> {
    fn should_run(&self) -> bool {
        self.started_at.expect("started_at should be set").elapsed() < self.duration
    }

    pub fn setup_ruby_version_config(
        versions: &mut libbpf_rs::Map,
    ) -> Result<HashMap<RubyVersion, u32>> {
        // Set the Ruby versions config
        let mut supported_ruby_versions = HashMap::new();
        for (i, ruby_version_config_yaml) in ruby_version_configs_yaml.iter().enumerate() {
            let ruby_version_config: RubyVersionOffsets =
                serde_yaml::from_str(ruby_version_config_yaml)?;
            let key: u32 = i.try_into().unwrap();
            let value = unsafe { any_as_u8_slice(&ruby_version_config) };
            versions.update(&key.to_le_bytes(), value, MapFlags::ANY)?;
            supported_ruby_versions.insert(
                RubyVersion::new(
                    ruby_version_config.major_version,
                    ruby_version_config.minor_version,
                    ruby_version_config.patch_version,
                ),
                i as u32,
            );
        }
        Ok(supported_ruby_versions)
    }

    pub fn new(options: RbperfOptions) -> Self {
        if !arch::is_x86() {
            eprintln!("rbperf hasn't been thoroughly tested on non-x86 architectures");
        }
        let mut skel_builder = RbperfSkelBuilder::default();
        if options.verbose_libbpf_logging {
            skel_builder.obj_builder.debug(true);
        }
        let mut open_skel = skel_builder.open().unwrap();
        debug!("verbose_bpf_logging set to {}", options.verbose_bpf_logging);
        open_skel.rodata().verbose = options.verbose_bpf_logging;

        debug!("use_ringbuf set to {}", options.use_ringbuf);
        open_skel.rodata().use_ringbuf = options.use_ringbuf;

        open_skel.rodata().event_type = rbperf_event_type::from(options.event.clone());

        if options.disable_pid_race_detector {
            debug!("disabled pid race detector");
            open_skel.rodata().enable_pid_race_detector = false;
        }

        match options.event {
            RbperfEvent::Cpu { sample_freq: _ } => {
                for prog in open_skel.obj.progs_iter_mut() {
                    prog.set_prog_type(ProgramType::PerfEvent);
                }
            }
            RbperfEvent::Syscall(_) => {
                for prog in open_skel.obj.progs_iter_mut() {
                    prog.set_prog_type(ProgramType::Tracepoint);
                }
            }
        }

        let mut maps = open_skel.maps_mut();
        let events = maps.events();

        if options.use_ringbuf {
            events.set_type(MapType::RingBuf).unwrap();
            events.set_key_size(0).unwrap();
            events.set_value_size(0).unwrap();
            events.set_max_entries(512 * 1024).unwrap(); // 512KB
        } else {
            events.set_type(MapType::PerfEventArray).unwrap();
            events.set_key_size(4).unwrap();
            events.set_value_size(4).unwrap();
            events.set_max_entries(0).unwrap();
        }

        let mut bpf = open_skel.load().unwrap();
        for prog in bpf.obj.progs_iter() {
            debug!(
                "open prog: {} has {} intructions",
                prog.name(),
                prog.insn_cnt()
            );
        }

        let mut maps = bpf.maps_mut();
        let versions = maps.version_specific_offsets();
        let supported_ruby_versions = Self::setup_ruby_version_config(versions).unwrap();

        let (sender, receiver) = channel();
        Rbperf {
            bpf,
            started_at: None,
            duration: std::time::Duration::from_secs(10),
            sender: Arc::new(Mutex::new(sender)),
            receiver: Arc::new(Mutex::new(receiver)),
            supported_ruby_versions,
            event: options.event,
            use_ringbuf: options.use_ringbuf,
            enable_linenos: options.enable_linenos,
            stats: Stats::default(),
        }
    }

    fn add_process_info(&mut self, process_info: &ProcessInfo) -> Result<()> {
        // Set the per-process data
        let mut matching_version: Option<(&RubyVersion, u32)> = None;
        for (ruby_version, idx) in self.supported_ruby_versions.iter() {
            let v: Vec<i32> = process_info
                .ruby_version
                .split('.')
                .map(|x| x.parse::<i32>().unwrap())
                .collect();
            let (major, minor, patch) = (v[0], v[1], v[2]);

            if (major, minor, patch)
                == (
                    ruby_version.major_version,
                    ruby_version.minor_version,
                    ruby_version.patch_version,
                )
            {
                matching_version = Some((ruby_version, *idx));
            }
        }

        match matching_version {
            Some((version, idx)) => {
                info!(
                    "Adding config for version starting with {:?} at index {}",
                    version, idx
                );
                let process_data = ProcessData {
                    rb_frame_addr: process_info.ruby_main_thread_address(),
                    rb_version: idx,
                    start_time: 0,
                };

                let value = unsafe { any_as_u8_slice(&process_data) };

                let mut maps = self.bpf.maps_mut();
                let pid_to_rb_thread = maps.pid_to_rb_thread();
                pid_to_rb_thread.update(&process_info.pid.to_le_bytes(), value, MapFlags::ANY)?;
            }
            None => {
                panic!("Unsupported Ruby version");
            }
        }

        Ok(())
    }
    pub fn add_pid(&mut self, pid: Pid) -> Result<ProcessInfo> {
        // Fetch and add process info
        let process_info = ProcessInfo::new(pid)?;
        eprintln!("{process_info}");
        self.add_process_info(&process_info)?;

        Ok(process_info)
    }

    pub fn start(
        mut self,
        duration: std::time::Duration,
        profile: &mut Profile,
        runnable: Arc<AtomicBool>,
    ) -> Result<Stats> {
        debug!("profiling started");
        self.duration = duration;
        // Set up the perf buffer and perf events
        let mut sender = self.sender.clone();
        let mut fds = Vec::new();

        match self.event {
            RbperfEvent::Cpu { sample_freq } => {
                for i in 0..num_cpus::get() {
                    let perf_fd = unsafe { setup_perf_event(i.try_into().unwrap(), sample_freq) }?;
                    fds.push(perf_fd);
                }
            }
            RbperfEvent::Syscall(ref syscall_names) => {
                for name in syscall_names {
                    let perf_fd = unsafe { setup_syscall_event(name) }?;
                    fds.push(perf_fd);
                }
            }
        }

        let mut links = Vec::new();
        // prevent the links from being removed
        // https://github.com/libbpf/libbpf-rs/blob/5db2c5b37f7ce56c85c43df23e3114a3d87a786e/libbpf-rs/src/link.rs#L109

        for fd in fds {
            let prog = self.bpf.obj.prog_mut("on_event").unwrap();
            let link = prog.attach_perf_event(fd);
            links.push(link);
        }

        for prog in self.bpf.obj.progs_iter_mut() {
            debug!("program type {}", prog.prog_type());
        }

        // Insert Ruby stack reading program
        let idx: i32 = RBPERF_STACK_READING_PROGRAM_IDX.try_into().unwrap();
        let val = self.bpf.obj.prog("walk_ruby_stack").unwrap().fd();

        let mut maps = self.bpf.maps_mut();
        let programs = maps.programs();
        programs
            .update(&idx.to_le_bytes(), &val.to_le_bytes(), MapFlags::ANY)
            .unwrap();

        let maps = self.bpf.maps();
        let events = maps.events();

        let mut perfbuf = None;
        let mut ringbuf = None;

        if self.use_ringbuf {
            let mut builder = libbpf_rs::RingBufferBuilder::new();
            builder.add(events, |data: &[u8]| -> i32 {
                handle_event(&mut sender, 0, data);
                0
            })?;
            ringbuf = Some(builder.build()?);
        } else {
            let perf_buffer = PerfBufferBuilder::new(self.bpf.maps().events())
                .sample_cb(|cpu: i32, data: &[u8]| {
                    handle_event(&mut sender, cpu, data);
                })
                .lost_cb(|cpu, count| {
                    // TODO: self.stats.incomplete_stack_errors += 1;
                    handle_lost_events(cpu, count)
                })
                .build()?;
            perfbuf = Some(perf_buffer);
        }

        // Start polling
        self.started_at = Some(Instant::now());
        let timeout = Duration::from_millis(100);

        while self.should_run() && runnable.load(Ordering::SeqCst) {
            if self.use_ringbuf {
                if let Err(err) = ringbuf.as_ref().unwrap().poll(timeout) {
                    debug!("Polling ringbuf failed with {:?}", err);
                }
            } else if let Err(err) = perfbuf.as_ref().unwrap().poll(timeout) {
                debug!("Polling perfbuf failed with {:?}", err);
            }
        }

        // Read all the data and finish
        let stats = self.process(profile);
        Ok(stats)
    }

    fn process(mut self, profile: &mut Profile) -> Stats {
        let recv = self.receiver.clone();
        let maps = self.bpf.maps();
        let frame_table = maps.frame_table();
        let mut id_to_frame = HashMap::new();
        for stack_bytes in frame_table.keys() {
            match frame_table.lookup(&stack_bytes, MapFlags::ANY) {
                Ok(Some(id_bytes)) => {
                    let frame = unsafe { parse_frame(&stack_bytes) };
                    let id = u32::from_le_bytes(id_bytes.try_into().expect("parse frame id bytes"));
                    id_to_frame.insert(id, frame);
                }
                _ => continue,
            }
        }

        loop {
            let read = recv.lock().unwrap().try_recv();
            match read {
                Ok(recv_stack) => {
                    let mut read_frame_count = 0;
                    self.stats.total_events += 1;

                    if recv_stack.stack_status == ruby_stack_status_STACK_INCOMPLETE {
                        error!("truncated stack");
                        self.stats.truncated_stacks += 1;
                        continue;
                    }

                    if recv_stack.pid == 0 {
                        panic!("pid is zero, this should never happen");
                    }

                    let comm_bytes: Vec<u8> = recv_stack.comm.iter().map(|&c| c as u8).collect();
                    let comm = unsafe { str_from_u8_nul(&comm_bytes) };
                    if comm.is_err() {
                        self.stats.garbled_data_errors += 1;
                        continue;
                    }
                    let comm = comm.expect("comm should be valid unicode").to_string();
                    let mut frames: Vec<(String, String, Option<u32>)> = Vec::new();

                    for frame_id in &recv_stack.frames {
                        // Don't read past the last frame
                        if read_frame_count >= recv_stack.size {
                            break;
                        }

                        match id_to_frame.get(frame_id) {
                            Some(frame) => {
                                let method_name_bytes: Vec<u8> =
                                    frame.method_name.iter().map(|&c| c as u8).collect();
                                let path_name_bytes: Vec<u8> =
                                    frame.path.iter().map(|&c| c as u8).collect();

                                let method_name = unsafe { str_from_u8_nul(&method_name_bytes) };
                                if method_name.is_err() {
                                    self.stats.garbled_data_errors += 1;
                                    continue;
                                }
                                let method_name = method_name
                                    .expect("method name should be valid unicode")
                                    .to_string();

                                let path_name = unsafe { str_from_u8_nul(&path_name_bytes) };
                                if path_name.is_err() {
                                    self.stats.garbled_data_errors += 1;
                                    continue;
                                }
                                let path_name = path_name
                                    .expect("path name should be valid unicode")
                                    .to_string();

                                let lineno = if self.enable_linenos {
                                    Some(frame.lineno)
                                } else {
                                    None
                                };
                                frames.push((method_name, path_name, lineno));
                                read_frame_count += 1;
                            }
                            None => {
                                self.stats.map_reading_errors += 1;
                            }
                        }
                    }

                    // Add generated frames
                    if let RbperfEvent::Syscall(_) = self.event {
                        let syscall_number = syscalls::Sysno::from(recv_stack.syscall_id);
                        frames.push((
                            format!("{syscall_number}").to_string(),
                            "<syscall>".to_string(),
                            None,
                        ));
                    }

                    if recv_stack.size == read_frame_count {
                        profile.add_sample(recv_stack.pid as Pid, comm, frames);
                    } else if self.stats.stack_errors() == 0 {
                        error!(
                            "mismatched expected={} and received={} frame count",
                            recv_stack.size, read_frame_count
                        );
                    } else {
                        error!(
                            "mismatched expected={} and received={} frame count, stats {:?}",
                            recv_stack.size, read_frame_count, self.stats
                        );
                    }
                }

                // We have read all the elements in the channel
                Err(_) => {
                    return self.stats;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys;
    use nix::sys::signal::Signal;
    use nix::unistd::Pid;
    use project_root;
    use rand;
    use std::process::{Command, Stdio};
    use std::{thread, time::Duration};

    const DEFAULT_RUBY_VERSION: &str = "3.0.0";

    struct TestProcess {
        container_name: String,
        pid: Option<i32>,
    }
    impl TestProcess {
        fn new(program: &str, ruby_version: &str) -> Self {
            let test_random_id: u64 = rand::random();
            let container_name = format!("rbperf-test-container-{test_random_id}");

            let _ = Command::new("podman")
                .args([
                    "run",
                    "--rm",
                    "--name",
                    &container_name,
                    "-v",
                    // https://stackoverflow.com/questions/24288616/permission-denied-on-accessing-host-directory-in-docker
                    (format!(
                        "{}:/usr/src/myapp:z",
                        project_root::get_project_root()
                            .expect("Retrieve project root")
                            .display()
                    )
                    .as_str()),
                    "-w",
                    "/usr/src/myapp",
                    (format!("ruby:{ruby_version}").as_str()),
                    "ruby",
                    program,
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("Failed to start Ruby process");

            Self {
                container_name,
                pid: None,
            }
        }

        fn wait_for_container(&mut self) -> i32 {
            // TODO: Improve process ready detection
            let mut attempts = 0;
            let max_attempts = 30;
            let mut pid: Option<i32> = None;

            while attempts < max_attempts {
                let d = Command::new("podman")
                    .args(["inspect", "-f", "'{{.State.Pid}}'", &self.container_name])
                    .output()
                    .expect("Failed to start Podman inspect process");

                let mut pid_str = std::str::from_utf8(&d.stdout).unwrap().to_string();
                pid_str = pid_str.trim().to_string();
                println!("ruby container raw pid {pid_str:?}");

                if pid_str.is_empty() {
                    thread::sleep(Duration::from_millis(200));
                    attempts += 1;
                    continue;
                }

                pid_str = pid_str.trim_start_matches('\'').to_string();
                pid_str = pid_str.trim_end_matches('\'').to_string();

                assert_ne!(pid_str, "", "the ruby container did not start");

                pid = Some(pid_str.parse::<i32>().unwrap());
                println!("parsed ruby container pid {pid:?}");
                break;
            }

            //assert!(!pid.is_none());
            self.pid = pid;
            pid.unwrap()
        }
    }

    impl Drop for TestProcess {
        fn drop(&mut self) {
            sys::signal::kill(Pid::from_raw(self.pid.unwrap()), Signal::SIGKILL).expect("failed");
        }
    }

    #[test]
    fn test_cpu_profiling() {
        let mut tp = TestProcess::new("tests/programs/cpu_hog.rb", DEFAULT_RUBY_VERSION);
        let pid = tp.wait_for_container();
        // TODO: Improve process ready detection
        thread::sleep(Duration::from_millis(250));

        let options = RbperfOptions {
            event: RbperfEvent::Cpu { sample_freq: 977 },
            verbose_bpf_logging: true,
            use_ringbuf: false,
            verbose_libbpf_logging: false,
            disable_pid_race_detector: false,
            enable_linenos: false,
        };
        let mut r = Rbperf::new(options);
        r.add_pid(pid).unwrap();

        let duration = std::time::Duration::from_millis(1500);
        let mut profile = Profile::new();
        r.start(duration, &mut profile, Arc::new(AtomicBool::new(true)))
            .unwrap();
        let folded = profile.folded();
        println!("folded: {folded}");

        assert!(folded.contains("<main> - tests/programs/cpu_hog.rb;a1 - tests/programs/cpu_hog.rb;b1 - tests/programs/cpu_hog.rb;c1 - tests/programs/cpu_hog.rb;cpu - tests/programs/cpu_hog.rb;<native code>"));
    }

    #[test]
    fn test_ringbuf() {
        let mut tp = TestProcess::new("tests/programs/simple_two_stacks.rb", DEFAULT_RUBY_VERSION);
        let pid = tp.wait_for_container();
        thread::sleep(Duration::from_millis(250));

        let options = RbperfOptions {
            event: RbperfEvent::Syscall(vec!["enter_writev".to_string()]),
            verbose_bpf_logging: true,
            use_ringbuf: true,
            verbose_libbpf_logging: false,
            disable_pid_race_detector: false,
            enable_linenos: false,
        };
        let mut r = Rbperf::new(options);
        r.add_pid(pid).unwrap();

        let duration = std::time::Duration::from_millis(1500);
        let mut profile = Profile::new();
        r.start(duration, &mut profile, Arc::new(AtomicBool::new(true)))
            .unwrap();
        let folded = profile.folded();
        println!("folded: {folded}");

        assert!(folded.contains("<main> - tests/programs/simple_two_stacks.rb;a - tests/programs/simple_two_stacks.rb;b - tests/programs/simple_two_stacks.rb;c - tests/programs/simple_two_stacks.rb;d - tests/programs/simple_two_stacks.rb;e - tests/programs/simple_two_stacks.rb;say_hi1 - tests/programs/simple_two_stacks.rb"));
        assert!(folded.contains("<main> - tests/programs/simple_two_stacks.rb;a2 - tests/programs/simple_two_stacks.rb;b2 - tests/programs/simple_two_stacks.rb;c2 - tests/programs/simple_two_stacks.rb;say_hi2 - tests/programs/simple_two_stacks.rb"));
    }

    #[test]
    fn test_linenos() {
        let mut tp = TestProcess::new("tests/programs/simple_two_stacks.rb", DEFAULT_RUBY_VERSION);
        let pid = tp.wait_for_container();
        thread::sleep(Duration::from_millis(250));

        let options = RbperfOptions {
            event: RbperfEvent::Syscall(vec!["enter_writev".to_string()]),
            verbose_bpf_logging: true,
            use_ringbuf: false,
            verbose_libbpf_logging: false,
            disable_pid_race_detector: false,
            enable_linenos: true,
        };
        let mut r = Rbperf::new(options);
        r.add_pid(pid).unwrap();

        let duration = std::time::Duration::from_millis(1500);
        let mut profile = Profile::new();
        r.start(duration, &mut profile, Arc::new(AtomicBool::new(true)))
            .unwrap();
        let folded = profile.folded();
        println!("folded: {folded}");

        assert!(folded.contains("<main> - tests/programs/simple_two_stacks.rb:52;a - tests/programs/simple_two_stacks.rb:26;b - tests/programs/simple_two_stacks.rb:22;c - tests/programs/simple_two_stacks.rb:18;d - tests/programs/simple_two_stacks.rb:14;e - tests/programs/simple_two_stacks.rb:10;say_hi1 - tests/programs/simple_two_stacks.rb:6;<native code> - <unknown>:0;<native code> - <unknown>:0"));
        assert!(folded.contains("<main> - tests/programs/simple_two_stacks.rb:52;a2 - tests/programs/simple_two_stacks.rb:43;b2 - tests/programs/simple_two_stacks.rb:39;c2 - tests/programs/simple_two_stacks.rb:35;say_hi2 - tests/programs/simple_two_stacks.rb:31;<native code> - <unknown>:0;<native code>"));
    }

    #[test]
    fn test_verbose_bpf_logging_disabled() {
        let mut tp = TestProcess::new("tests/programs/simple_two_stacks.rb", DEFAULT_RUBY_VERSION);
        let pid = tp.wait_for_container();
        thread::sleep(Duration::from_millis(250));

        let options = RbperfOptions {
            event: RbperfEvent::Syscall(vec!["enter_writev".to_string()]),
            verbose_bpf_logging: false,
            use_ringbuf: false,
            verbose_libbpf_logging: false,
            disable_pid_race_detector: false,
            enable_linenos: false,
        };
        let mut r = Rbperf::new(options);
        r.add_pid(pid).unwrap();

        let duration = std::time::Duration::from_millis(1500);
        let mut profile = Profile::new();
        r.start(duration, &mut profile, Arc::new(AtomicBool::new(true)))
            .unwrap();
        let folded = profile.folded();
        println!("folded: {folded}");

        assert!(folded.contains("<main> - tests/programs/simple_two_stacks.rb;a - tests/programs/simple_two_stacks.rb;b - tests/programs/simple_two_stacks.rb;c - tests/programs/simple_two_stacks.rb;d - tests/programs/simple_two_stacks.rb;e - tests/programs/simple_two_stacks.rb;say_hi1 - tests/programs/simple_two_stacks.rb"));
        assert!(folded.contains("<main> - tests/programs/simple_two_stacks.rb;a2 - tests/programs/simple_two_stacks.rb;b2 - tests/programs/simple_two_stacks.rb;c2 - tests/programs/simple_two_stacks.rb;say_hi2 - tests/programs/simple_two_stacks.rb"));
    }

    #[test]
    fn test_big_stack() {
        let mut tp = TestProcess::new("tests/programs/big_stack.rb", DEFAULT_RUBY_VERSION);
        let pid = tp.wait_for_container();
        thread::sleep(Duration::from_millis(250));

        let options = RbperfOptions {
            event: RbperfEvent::Syscall(vec!["enter_writev".to_string()]),
            verbose_bpf_logging: false,
            use_ringbuf: false,
            verbose_libbpf_logging: false,
            disable_pid_race_detector: false,
            enable_linenos: false,
        };
        let mut r = Rbperf::new(options);
        r.add_pid(pid).unwrap();

        let duration = std::time::Duration::from_millis(1500);
        let mut profile = Profile::new();
        r.start(duration, &mut profile, Arc::new(AtomicBool::new(true)))
            .unwrap();
        let folded = profile.folded();
        println!("folded: {folded}");

        let mut expected = "<main> - tests/programs/big_stack.rb".to_string();
        for i in 1..100 {
            expected = format!("{};a_{} - (eval)", &expected, i);
        }
        println!("expected {expected} ");
        assert!(folded.contains(&expected));
    }

    macro_rules! rbperf_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
    #[test]
    fn $name() {

            let mut tp = TestProcess::new("tests/programs/simple_two_stacks.rb", $value);
            let pid = tp.wait_for_container();
            // TODO: Improve process ready detection
            thread::sleep(Duration::from_millis(250));

            let options = RbperfOptions {
                event: RbperfEvent::Syscall(vec!["enter_writev".to_string()]),
                verbose_bpf_logging: true,
                use_ringbuf: false,
                verbose_libbpf_logging: false,
                disable_pid_race_detector: false,
                enable_linenos: false,
            };
            let mut r = Rbperf::new(options);
            r.add_pid(pid).unwrap();

            let duration = std::time::Duration::from_millis(1500);
            let mut profile = Profile::new();
            r.start(duration, &mut profile, Arc::new(AtomicBool::new(true))).unwrap();
            let folded = profile.folded();
            println!("folded: {}", folded);

            // TODO: Improve assertions
            assert!(folded.contains("<main> - tests/programs/simple_two_stacks.rb;a - tests/programs/simple_two_stacks.rb;b - tests/programs/simple_two_stacks.rb;c - tests/programs/simple_two_stacks.rb;d - tests/programs/simple_two_stacks.rb;e - tests/programs/simple_two_stacks.rb;say_hi1 - tests/programs/simple_two_stacks.rb"));
            assert!(folded.contains("<main> - tests/programs/simple_two_stacks.rb;a2 - tests/programs/simple_two_stacks.rb;b2 - tests/programs/simple_two_stacks.rb;c2 - tests/programs/simple_two_stacks.rb;say_hi2 - tests/programs/simple_two_stacks.rb"));
        }
    )*
    }}

    rbperf_tests! {
        rbperf_test_2_6_0: "2.6.0",
        rbperf_test_2_6_3: "2.6.3",
        rbperf_test_2_7_1: "2.7.1",
        rbperf_test_2_7_4: "2.7.4",
        rbperf_test_2_7_6: "2.7.6",
        rbperf_test_3_0_0: "3.0.0",
        rbperf_test_3_0_4: "3.0.4",
        rbperf_test_3_1_2: "3.1.2",
        rbperf_test_3_1_3: "3.1.3",
        rbperf_test_3_2_0: "3.2.0",
        rbperf_test_3_2_1: "3.2.1",
    }
}
