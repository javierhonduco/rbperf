use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use libbpf_rs::{num_possible_cpus, MapFlags, PerfBufferBuilder, ProgramType};

use anyhow::Result;
use log::{debug, error, info, log_enabled, Level};
use proc_maps::Pid;

use crate::arch;
use crate::bpf::*;
use crate::events::{setup_perf_event, setup_syscall_event};
use crate::process::ProcessInfo;
use crate::profile::Profile;
use crate::ruby_readers::{any_as_u8_slice, parse_frame, parse_stack, str_from_u8_nul};
use crate::ruby_versions::{
    ruby_2_6_0, ruby_2_6_3, ruby_2_7_1, ruby_2_7_4, ruby_2_7_6, ruby_3_0_0, ruby_3_0_4, ruby_3_1_2,
};
use crate::{ProcessData, RubyStack, RBPERF_STACK_READING_PROGRAM_IDX};

pub enum RbperfEvent {
    Cpu { sample_period: u64 },
    Syscall(String),
}
pub struct Rbperf<'a> {
    bpf: RbperfSkel<'a>,
    duration: std::time::Duration,
    started_at: Option<Instant>,
    sender: Arc<Mutex<std::sync::mpsc::Sender<RubyStack>>>,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<RubyStack>>>,
    ruby_versions: Vec<RubyVersion>,
    event: RbperfEvent,
}

pub struct RbperfOptions {
    pub event: RbperfEvent,
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

#[derive(Debug)]
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

    pub fn setup_ruby_version_config(versions: &mut libbpf_rs::Map) -> Result<Vec<RubyVersion>> {
        // Set the Ruby versions config
        let ruby_version_configs = vec![
            ruby_2_6_0, ruby_2_6_3, ruby_2_7_1, ruby_2_7_4, ruby_2_7_6, ruby_3_0_0, ruby_3_0_4,
            ruby_3_1_2,
        ];
        let mut ruby_versions: Vec<RubyVersion> = vec![];
        for (i, ruby_version_config) in ruby_version_configs.iter().enumerate() {
            let key: u32 = i.try_into().unwrap();
            let value = unsafe { any_as_u8_slice(ruby_version_config) };
            versions.update(&key.to_le_bytes(), value, MapFlags::ANY)?;
            ruby_versions.push(RubyVersion::new(
                ruby_version_config.major_version,
                ruby_version_config.minor_version,
                ruby_version_config.patch_version,
            ));
        }
        Ok(ruby_versions)
    }

    pub fn new(options: RbperfOptions) -> Self {
        if !arch::is_x86() {
            eprintln!("rbperf hasn't been thoroughly tested on non-x86 architectures");
        }

        let mut skel_builder = RbperfSkelBuilder::default();
        if log_enabled!(Level::Debug) {
            skel_builder.obj_builder.debug(true);
        }
        let mut open_skel = skel_builder.open().unwrap();
        match options.event {
            RbperfEvent::Cpu { sample_period: _ } => {
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
        let mut bpf = open_skel.load().unwrap();

        let mut maps = bpf.maps_mut();
        let versions = maps.version_specific_offsets();
        let ruby_versions = Self::setup_ruby_version_config(versions).unwrap();

        let (sender, receiver) = channel();
        Rbperf {
            bpf,
            started_at: None,
            duration: std::time::Duration::from_secs(10),
            sender: Arc::new(Mutex::new(sender)),
            receiver: Arc::new(Mutex::new(receiver)),
            ruby_versions,
            event: options.event,
        }
    }

    fn add_process_info(&mut self, process_info: ProcessInfo) -> Result<()> {
        // Set the per-process data
        let mut matching_version: Option<(i32, &RubyVersion)> = None;
        for (i, ruby_version) in self.ruby_versions.iter().enumerate() {
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
                matching_version = Some((i.try_into().unwrap(), ruby_version));
            }
        }

        match matching_version {
            Some((idx, version)) => {
                info!(
                    "Adding config for version starting with {:?} at index {}",
                    version, idx
                );
                let process_data = ProcessData {
                    rb_frame_addr: process_info.ruby_main_thread_address(),
                    rb_version: idx,
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
    pub fn add_pid(&mut self, pid: Pid) -> Result<()> {
        // Fetch and add process info
        let process_info = ProcessInfo::new(pid)?;
        eprintln!("{}", process_info);
        self.add_process_info(process_info)?;

        Ok(())
    }

    pub fn start(mut self, duration: std::time::Duration, profile: &mut Profile) -> Result<()> {
        debug!("profiling started");
        self.duration = duration;
        // Set up the perf buffer and perf events
        let mut sender = self.sender.clone();
        let perf = PerfBufferBuilder::new(self.bpf.maps().events())
            .sample_cb(|cpu: i32, data: &[u8]| {
                handle_event(&mut sender, cpu, data);
            })
            .lost_cb(handle_lost_events)
            .build()?;

        let mut fds = Vec::new();

        match self.event {
            RbperfEvent::Cpu { sample_period } => {
                for i in 0..num_possible_cpus()? {
                    let perf_fd =
                        unsafe { setup_perf_event(i.try_into().unwrap(), sample_period) }?;
                    fds.push(perf_fd);
                }
            }
            RbperfEvent::Syscall(ref name) => {
                let perf_fd = unsafe { setup_syscall_event(name) }?;
                fds.push(perf_fd);
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
        let val = self.bpf.obj.prog("read_ruby_stack").unwrap().fd();

        let mut maps = self.bpf.maps_mut();
        let programs = maps.programs();
        programs
            .update(&idx.to_le_bytes(), &val.to_le_bytes(), MapFlags::ANY)
            .unwrap();

        // Start polling
        self.started_at = Some(Instant::now());
        while self.should_run() {
            perf.poll(Duration::from_millis(100))?;
        }

        // Read all the data and finish
        self.process(profile);

        Ok(())
    }

    fn process(self, profile: &mut Profile) {
        let recv = self.receiver.clone();
        let maps = self.bpf.maps();
        let id_to_stack = maps.id_to_stack();

        //let mut reading_errors = 0;
        loop {
            match recv.lock().unwrap().try_recv() {
                Ok(data) => {
                    let comm_bytes: Vec<u8> = data.comm.iter().map(|&c| c as u8).collect();
                    let comm = unsafe { str_from_u8_nul(&comm_bytes) };
                    if comm.is_err() {
                        profile.add_error();
                        continue;
                    }
                    let comm = comm.unwrap().to_string();
                    let mut frames: Vec<(String, String)> = Vec::new();

                    // write a custom fmt for debugging
                    if data.stack_status == 0 {
                        let mut read_frame_count = 0;

                        if data.pid == 0 {
                            error!("kernel?");
                        } else {
                            for frame in &data.frames {
                                // Don't read past the last frame
                                if read_frame_count >= data.size {
                                    continue;
                                }

                                if *frame == 0 {
                                    profile.add_error();
                                    // debug!("stack incomplete");
                                } else {
                                    let frame_bytes = id_to_stack
                                        .lookup(&frame.to_le_bytes(), MapFlags::ANY)
                                        .unwrap();
                                    let frame = unsafe { parse_frame(&frame_bytes.unwrap()) };
                                    let method_name_bytes: Vec<u8> =
                                        frame.method_name.iter().map(|&c| c as u8).collect();
                                    let path_name_bytes: Vec<u8> =
                                        frame.path.iter().map(|&c| c as u8).collect();

                                    let method_name =
                                        unsafe { str_from_u8_nul(&method_name_bytes) };
                                    if method_name.is_err() {
                                        profile.add_error();
                                        continue;
                                    }
                                    let method_name = method_name.unwrap().to_string();

                                    let path_name = unsafe { str_from_u8_nul(&path_name_bytes) };

                                    if path_name.is_err() {
                                        profile.add_error();
                                        continue;
                                    }
                                    let path_name = path_name.unwrap().to_string();

                                    // write a custom fmt for debugging
                                    frames.push((method_name, path_name));

                                    read_frame_count += 1;
                                }
                            }
                        }
                        if data.size != read_frame_count {
                            debug!(
                                "mismatched expected={} and received={} frame count",
                                data.size, read_frame_count
                            );
                            profile.add_error();
                        } else {
                            profile.add_sample(data.pid as Pid, comm, frames);
                        }
                    } else {
                        // not complete
                        // todo: add stats
                        debug!("stack incomplete");
                    }
                }
                // We have read all the elements in the channel
                Err(_) => {
                    return;
                }
            }
        }

        //  println!("got {} samples with errors while reading the heap", reading_errors);
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

    macro_rules! rbperf_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
    #[test]
    fn $name() {
            let test_random_id: u64 = rand::random();
            let container_name = format!("rbperf-test-container-{}", test_random_id);

            let mut ruby_process = Command::new("podman")
                .args([
                    "run",
                    "--rm",
                    "--name",
                    container_name.as_str(),
                    "-v",
                    // https://stackoverflow.com/questions/24288616/permission-denied-on-accessing-host-directory-in-docker
                    &format!("{}:/usr/src/myapp:z", project_root::get_project_root().expect("Retrieve project root").display()).as_str(),
                    "-w",
                    "/usr/src/myapp",
                    &format!("ruby:{}", $value).as_str(),
                    "ruby",
                    "tests/programs/simple_two_stacks.rb",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("Failed to start Ruby process");

            let mut attempts = 0;
            let max_attempts = 20;
            let mut pid: Option<i32> = None;

            while attempts < max_attempts {
                let d = Command::new("podman")
                    .args([
                        "inspect",
                        "-f",
                        "'{{.State.Pid}}'",
                        container_name.as_str(),
                    ])
                    .output()
                    .expect("Failed to start Podman inspect process");

                let mut pid_str = std::str::from_utf8(&d.stdout).unwrap().to_string();
                pid_str = pid_str.trim().to_string();
                println!("docker container {:?}", pid_str);

                if pid_str == "" {
                    thread::sleep(Duration::from_millis(200));
                    attempts += 1;
                    continue;
                }

                pid_str = pid_str.trim_start_matches("'").to_string();
                pid_str = pid_str.trim_end_matches("'").to_string();

                pid = Some(pid_str.parse::<i32>().unwrap());
                println!("parsed docker container {:?}", pid);
                break;
            }

            // TODO: Improve process ready detection
            thread::sleep(Duration::from_millis(250));

            let options = RbperfOptions {
                event: RbperfEvent::Syscall("enter_writev".to_string()),
            };
            let mut r = Rbperf::new(options);
            r.add_pid(pid.unwrap()).unwrap();

            let duration = std::time::Duration::from_millis(1500);
            let mut profile = Profile::new();
            r.start(duration, &mut profile).unwrap();
            let folded = profile.folded();
            println!("folded: {}", folded);

            // TODO: Improve assertions
            assert!(folded.contains("<main> - tests/programs/simple_two_stacks.rb;a - tests/programs/simple_two_stacks.rb;b - tests/programs/simple_two_stacks.rb;c - tests/programs/simple_two_stacks.rb;d - tests/programs/simple_two_stacks.rb;e - tests/programs/simple_two_stacks.rb;say_hi1 - tests/programs/simple_two_stacks.rb"));
            assert!(folded.contains("<main> - tests/programs/simple_two_stacks.rb;a2 - tests/programs/simple_two_stacks.rb;b2 - tests/programs/simple_two_stacks.rb;c2 - tests/programs/simple_two_stacks.rb;say_hi2 - tests/programs/simple_two_stacks.rb"));

            // TODO: This doesn't seem to work
            ruby_process
                .kill()
                .expect("Killing the test process failed");
            sys::signal::kill(Pid::from_raw(pid.unwrap()), Signal::SIGKILL).expect("failed");

        }
    )*
    }}

    rbperf_tests! {
        rbperf_test_2_6_0: "2.6.0",
        rbperf_test_2_6_3: "2.6.3",
        rbperf_test_2_7_1: "2.7.1",
        rbperf_test_2_7_6: "2.7.6",
        rbperf_test_3_0_0: "3.0.0",
        rbperf_test_3_0_4: "3.0.4",
        rbperf_test_3_1_2: "3.1.2",
    }
}
