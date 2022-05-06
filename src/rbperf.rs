use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use bcc::perf_event::{Event, PerfMapBuilder, SoftwareEvent};
use bcc::{BPFBuilder, BpfProgType, PerfEvent, BPF};
use core::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use proc_maps::Pid;

use crate::process::ProcessInfo;
use crate::profile::Profile;
use crate::ruby_readers::{
    any_as_u8_slice, parse_frame, parse_struct, str_from_u8_nul_utf8_unchecked,
};
use crate::{ProcessData, RubyStack, RubyVersionOffsets};

struct Inner {
    runnable: AtomicBool,
}

impl Inner {
    fn should_run(&self) -> bool {
        self.runnable.load(Ordering::SeqCst)
    }
}
pub struct Rbperf {
    bpf: BPF,
    inner: Arc<Inner>,
    duration: std::time::Duration,
    started_at: Instant,
    sender: Arc<Mutex<std::sync::mpsc::Sender<RubyStack>>>,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<RubyStack>>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Rbperf {
    pub fn profile_cpu(
        &mut self,
        sample_period: u64,
        duration: std::time::Duration,
    ) -> Result<Profile> {
        println!("= profiling started");
        self.duration = duration;
        // Set the CRuby configuration
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
        let mut versions = self.bpf.table("version_specific_offsets")?;
        versions.set(&mut key.to_le_bytes(), &mut value)?;

        // Set up the BPF programs
        let mut programs = self.bpf.table("programs")?;
        let idx: i32 = 0;
        let val = self
            .bpf
            .load_func("read_ruby_frames", BpfProgType::PerfEvent)?;

        programs.set(&mut idx.to_le_bytes(), &mut val.to_le_bytes())?;

        // Set up perf events
        let table = self.bpf.table("events")?;

        let mut perf_map = PerfMapBuilder::new(table, || self.perf_data_callback()).build()?;
        let _ = PerfEvent::new()
            .handler("on_event")
            .event(Event::Software(SoftwareEvent::CpuClock))
            .sample_period(Some(sample_period))
            .attach(&mut self.bpf);

        let inner = self.inner.clone();
        let t = thread::spawn(move || {
            while inner.should_run() {
                perf_map.poll(100);
            }
        });
        self.threads.push(t);

        let p = self.process();
        self.join_threads();
        Ok(p)
    }

    pub fn add_pid(&self, pid: Pid) -> Result<()> {
        // todo:
        // - add process to global structure
        // - error handling

        // Set the process configuration
        let mut pid_to_rb_thread = self.bpf.table("pid_to_rb_thread")?;

        // Fetch process info
        let process_info = ProcessInfo::new(pid)?;
        println!("Pid: {}", process_info.pid);
        println!("Libruby: {:?}", process_info.libruby);
        println!(
            "Ruby main thread address: {:x}",
            process_info.ruby_main_thread_address()
        );
        println!(
            "Process base address: {:x}",
            process_info.process_base_address
        );
        println!("Ruby version: {}", process_info.ruby_version);
        println!();

        let key: i32 = 3; // mismatch
        let process_data = ProcessData {
            rb_frame_addr: process_info.ruby_main_thread_address(),
            rb_version: key,
        };

        println!("~~ {:?}", process_data);
        let mut value = unsafe { any_as_u8_slice(&process_data) };
        pid_to_rb_thread.set(&mut pid.to_le_bytes(), &mut value)?;

        Ok(())
    }

    fn perf_data_callback(&self) -> Box<dyn FnMut(&[u8]) + Send> {
        let tx = self.sender.clone();
        Box::new(move |x| {
            let data = unsafe { parse_struct(x) };
            tx.lock().unwrap().send(data).unwrap();
        })
    }

    fn process(&mut self) -> Profile {
        let recv = self.receiver.clone();
        let mut id_to_stack = self.bpf.table("id_to_stack").unwrap();

        let mut profile = Profile::new();
        //let mut reading_errors = 0;

        while self.should_run() {
            if let Ok(data) = recv.lock().unwrap().try_recv() {
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
                                // println!("Fetching frame with id: {}", frame);
                                let frame_thing = id_to_stack.get(&mut frame.to_le_bytes());
                                let t = unsafe { parse_frame(&frame_thing.unwrap()) };
                                let method_name: Vec<u8> =
                                    t.method_name.iter().map(|&c| c as u8).collect();
                                let path_name: Vec<u8> = t.path.iter().map(|&c| c as u8).collect();

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
                // todo: check the error code of reading strings
            }
        }

        //println!("got {} samples with errors while reading the heap", reading_errors);

        profile
    }

    pub fn join_threads(&mut self) {
        let mut thread = self.threads.pop();

        if let Some(handle) = thread.take() {
            handle.join().expect("failed to join thread");
        }
    }

    fn should_run(&self) -> bool {
        let runnable = self.started_at.elapsed() < self.duration;
        self.inner.runnable.store(runnable, Ordering::SeqCst);
        runnable
    }

    pub fn new() -> Self {
        let code = include_str!("../bpf/rbperf.c");

        let bpf = BPFBuilder::new(code).unwrap().build().unwrap();

        let (sender, receiver) = channel();
        Rbperf {
            bpf: bpf,
            inner: Arc::new(Inner {
                runnable: AtomicBool::new(true),
            }),
            started_at: Instant::now(),
            duration: std::time::Duration::from_secs(10),
            sender: Arc::new(Mutex::new(sender)),
            receiver: Arc::new(Mutex::new(receiver)),
            threads: Vec::new(),
        }
    }
}
