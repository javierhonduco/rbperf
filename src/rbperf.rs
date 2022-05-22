use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use libbpf_rs::{num_possible_cpus, MapFlags, PerfBufferBuilder};

use anyhow::Result;
use proc_maps::Pid;

use crate::bpf::*;
use crate::events::setup_perf_event;
use crate::process::ProcessInfo;
use crate::profile::Profile;
use crate::ruby_readers::{
    any_as_u8_slice, parse_frame, parse_struct, str_from_u8_nul_utf8_unchecked,
};
use crate::{ProcessData, RubyStack, RubyVersionOffsets};

pub struct Rbperf<'a> {
    bpf: RbperfSkel<'a>,
    duration: std::time::Duration,
    started_at: Instant,
    sender: Arc<Mutex<std::sync::mpsc::Sender<RubyStack>>>,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<RubyStack>>>,
    ruby_versions: Vec<RubyVersion>,
}

fn handle_event(
    sender: &mut Arc<Mutex<std::sync::mpsc::Sender<RubyStack>>>,
    _cpu: i32,
    data: &[u8],
) {
    let tx = sender.clone();
    let data = unsafe { parse_struct(data) };
    tx.lock().unwrap().send(data).unwrap();
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
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
        self.started_at.elapsed() < self.duration
    }

    pub fn setup_ruby_version_config(versions: &mut libbpf_rs::Map) -> Result<Vec<RubyVersion>> {
        // Set the Ruby versions config

        let ruby_2_5_0 = RubyVersionOffsets {
            major_version: 2,
            minor_version: 5,
            patch_version: 0,
            vm_offset: 0x20,
            vm_size_offset: 0x28,
            control_frame_t_sizeof: 0x30,
            cfp_offset: 0x30,
            label_offset: 0x18,
            path_flavour: 0,
            line_info_size_offset: 0xC0,
            line_info_table_offset: 0x68,
            lineno_offset: 0x4,
        };

        let ruby_2_6_0 = RubyVersionOffsets {
            major_version: 2,
            minor_version: 6,
            patch_version: 0,
            vm_offset: 0x0,
            vm_size_offset: 0x8,
            control_frame_t_sizeof: 0x38,
            cfp_offset: 0x10,
            label_offset: 0x10,
            path_flavour: 1,
            line_info_size_offset: 0x78 + 0x10,
            line_info_table_offset: 0x78,
            lineno_offset: 0x0,
        };

        let mut ruby_2_6_3 = ruby_2_6_0.clone();
        ruby_2_6_3.minor_version = 6;
        ruby_2_6_3.patch_version = 3;

        let mut ruby_2_7_1 = ruby_2_6_0.clone();
        ruby_2_7_1.minor_version = 7;
        ruby_2_7_1.patch_version = 1;

        let mut ruby_2_7_4 = ruby_2_6_0.clone();
        ruby_2_7_4.minor_version = 7;
        ruby_2_7_4.patch_version = 4;

        let ruby_3_0_0 = RubyVersionOffsets {
            major_version: 3,
            minor_version: 0,
            patch_version: 0,
            vm_offset: 0x0,
            vm_size_offset: 0x8,
            control_frame_t_sizeof: 0x38,
            cfp_offset: 0x10,
            label_offset: 0x10,
            path_flavour: 1,
            line_info_size_offset: 0x78 + 0x10,
            line_info_table_offset: 0x78,
            lineno_offset: 0x0,
        };

        let mut ruby_3_0_4 = ruby_3_0_0.clone();
        ruby_3_0_4.minor_version = 0;
        ruby_3_0_4.patch_version = 4;

        let mut ruby_3_1_2 = ruby_3_0_0.clone();
        ruby_3_1_2.minor_version = 1;
        ruby_3_1_2.patch_version = 2;

        let ruby_version_configs = vec![
            ruby_2_5_0, ruby_2_6_0, ruby_2_6_3, ruby_2_7_1, ruby_2_7_4, ruby_3_0_0, ruby_3_0_4,
        ];
        let mut ruby_versions: Vec<RubyVersion> = vec![];
        for (i, ruby_version_config) in ruby_version_configs.iter().enumerate() {
            let key: u32 = i.try_into().unwrap();
            let mut value = unsafe { any_as_u8_slice(ruby_version_config) };
            versions.update(&mut key.to_le_bytes(), &mut value, MapFlags::ANY)?;
            ruby_versions.push(RubyVersion::new(
                ruby_version_config.major_version,
                ruby_version_config.minor_version,
                ruby_version_config.patch_version,
            ));
        }
        Ok(ruby_versions)
    }

    pub fn new() -> Self {
        let skel_builder = RbperfSkelBuilder::default();
        // skel_builder.obj_builder.debug(true);
        let open_skel = skel_builder.open().unwrap();
        let mut bpf = open_skel.load().unwrap();

        let mut maps = bpf.maps_mut();
        let versions = maps.version_specific_offsets();
        let ruby_versions = Self::setup_ruby_version_config(versions).unwrap();

        let (sender, receiver) = channel();
        Rbperf {
            bpf: bpf,
            started_at: Instant::now(),
            duration: std::time::Duration::from_secs(10),
            sender: Arc::new(Mutex::new(sender)),
            receiver: Arc::new(Mutex::new(receiver)),
            ruby_versions: ruby_versions,
        }
    }

    fn add_process_info(&mut self, process_info: ProcessInfo) -> Result<()> {
        // Set the per-process data
        let mut matching_version: Option<(i32, &RubyVersion)> = None;
        for (i, ruby_version) in self.ruby_versions.iter().enumerate() {
            let v: Vec<i32> = process_info
                .ruby_version
                .split(".")
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
                println!(
                    "Adding config for version starting with {:?} at index {}",
                    version, idx
                );
                let process_data = ProcessData {
                    rb_frame_addr: process_info.ruby_main_thread_address(),
                    rb_version: idx,
                };

                let mut value = unsafe { any_as_u8_slice(&process_data) };

                let mut maps = self.bpf.maps_mut();
                let pid_to_rb_thread = maps.pid_to_rb_thread();
                pid_to_rb_thread.update(
                    &mut process_info.pid.to_le_bytes(),
                    &mut value,
                    MapFlags::ANY,
                )?;
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
        println!("Process info: {}", process_info);
        self.add_process_info(process_info)?;

        Ok(())
    }

    pub fn profile_cpu(
        mut self,
        sample_period: u64,
        duration: std::time::Duration,
        profile: &mut Profile,
    ) -> Result<()> {
        println!("= profiling started");
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
        for i in 0..num_possible_cpus()? {
            let perf_fd = unsafe { setup_perf_event(i.try_into().unwrap(), sample_period) }?;
            fds.push(perf_fd);
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
            println!("progs {}", prog.prog_type());
        }

        // Set the tail call map
        let idx: i32 = 0;
        let val = self.bpf.obj.prog("read_ruby_frames").unwrap().fd();

        let mut maps = self.bpf.maps_mut();
        let programs = maps.programs();
        programs
            .update(
                &mut idx.to_le_bytes(),
                &mut val.to_le_bytes(),
                MapFlags::ANY,
            )
            .unwrap();

        // Start polling
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
                    let c: Vec<u8> = data.comm.iter().map(|&c| c as u8).collect();
                    let comm = unsafe { str_from_u8_nul_utf8_unchecked(&c).to_string() };
                    let mut frames: Vec<(String, String)> = Vec::new();

                    // write a custom fmt for debugging
                    if data.stack_status == 0 {
                        let mut read_frame_count = 0;

                        if data.pid == 0 {
                            println!("warn: kernel?");
                        } else {
                            for frame in &data.frames {
                                if *frame == 0 {
                                    // println!("warn: stack incomplete");
                                } else {
                                    let frame_thing = id_to_stack
                                        .lookup(&mut frame.to_le_bytes(), MapFlags::ANY)
                                        .unwrap();
                                    let t = unsafe { parse_frame(&frame_thing.unwrap()) };
                                    let method_name: Vec<u8> =
                                        t.method_name.iter().map(|&c| c as u8).collect();
                                    let path_name: Vec<u8> =
                                        t.path.iter().map(|&c| c as u8).collect();

                                    // write a custom fmt for debugging
                                    frames.push((
                                        unsafe {
                                            str_from_u8_nul_utf8_unchecked(&method_name).to_string()
                                        },
                                        unsafe {
                                            str_from_u8_nul_utf8_unchecked(&path_name).to_string()
                                        },
                                    ));

                                    read_frame_count += 1;
                                }
                            }
                        }
                        if read_frame_count != data.size {
                            // println!("warn: mismatched expected and received frame count");
                            profile.add_error();
                        } else {
                            profile.add_sample(data.pid as Pid, comm, frames);
                        }
                    } else {
                        // not complete
                        // todo: add stats
                        println!("warn: stack incomplete");
                    }
                }
                // todo: check the error code of reading strings
                Err(_err) => {
                    // println!("error: {}", err);
                    return;
                }
            }
        }

        //println!("got {} samples with errors while reading the heap", reading_errors);
    }
}
