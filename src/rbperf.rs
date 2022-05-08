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

impl<'a> Rbperf<'a> {
    fn should_run(&self) -> bool {
        self.started_at.elapsed() < self.duration
    }

    pub fn setup_ruby_version_config(versions: &mut libbpf_rs::Map) -> Result<()> {
        // Set the Ruby versions config
        let offset = RubyVersionOffsets {
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
        let key: u32 = 3;
        let mut value = unsafe { any_as_u8_slice(&offset) };

        versions.update(&mut key.to_le_bytes(), &mut value, MapFlags::ANY)?;

        Ok(())
    }

    pub fn new() -> Self {
        let mut skel_builder = RbperfSkelBuilder::default();
        skel_builder.obj_builder.debug(true);
        let open_skel = skel_builder.open().unwrap();
        let mut bpf = open_skel.load().unwrap();

        let mut maps = bpf.maps_mut();
        let versions = maps.version_specific_offsets();
        Self::setup_ruby_version_config(versions).unwrap();

        let (sender, receiver) = channel();
        Rbperf {
            bpf: bpf,
            started_at: Instant::now(),
            duration: std::time::Duration::from_secs(10),
            sender: Arc::new(Mutex::new(sender)),
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    fn add_process_info(&mut self, process_info: ProcessInfo) -> Result<()> {
        // Set the per-process data
        let key: i32 = 3;

        let process_data = ProcessData {
            rb_frame_addr: process_info.ruby_main_thread_address(),
            rb_version: key, //  we would have to to find the mapping for this version
        };

        let mut value = unsafe { any_as_u8_slice(&process_data) };

        let mut maps = self.bpf.maps_mut();
        let pid_to_rb_thread = maps.pid_to_rb_thread();
        pid_to_rb_thread.update(
            &mut process_info.pid.to_le_bytes(),
            &mut value,
            MapFlags::ANY,
        )?;

        Ok(())
    }
    pub fn add_pid(&mut self, pid: Pid) -> Result<()> {
        // Fetch and add process info
        let process_info = ProcessInfo::new(pid)?;
        println!("Pid: {:?}", process_info.pid);
        self.add_process_info(process_info)?;

        Ok(())
    }

    pub fn profile_cpu(
        mut self,
        sample_period: u64,
        duration: std::time::Duration,
    ) -> Result<Profile> {
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
        let p = self.process();

        Ok(p)
    }

    fn process(self) -> Profile {
        let recv = self.receiver.clone();
        let maps = self.bpf.maps();
        let id_to_stack = maps.id_to_stack();

        let mut profile = Profile::new();
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
                    return profile;
                }
            }
        }

        //println!("got {} samples with errors while reading the heap", reading_errors);
    }
}
