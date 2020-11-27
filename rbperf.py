# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import os
import sys
import pkg_resources

from bcc import BPF, PerfType, PerfSWConfig, USDT
from ctypes import Structure, c_ulonglong, c_ulong, c_uint, c_int
import sys

from proto import rbperf_pb2
from utils import (
    rb_thread_address,
    max_stacks_for_kernel,
    read_userspace_address_space,
    process_exists,
    safely_decode_bytes,
)
from version_specific_config import offsets_for_version, index_for_version


class ProcessData(Structure):
    _fields_ = [("rb_frame_addr", c_ulonglong), ("rb_version", c_int)]


class RubyBPFStackWalker:
    BPF_FUNCTION_NAME = b"on_event"
    usdt_contexts = []

    def __init__(
        self, pids, sample_handler, max_stacks=None, bpf_programs_count=None,
    ):
        self.pids = set()
        self.queue = []
        self.sample_handler = sample_handler
        self.page_count = 64
        if max_stacks is None:
            max_stacks = max_stacks_for_kernel()
        self.max_stacks_per_program = max_stacks
        if bpf_programs_count is None:
            bpf_programs_count = 3
        self.bpf_programs_count = bpf_programs_count
        self.load_bpf()
        self.add_version_specific_offsets()
        self.add_pids(pids)

    def load_bpf(self):
        bpf_program_path = pkg_resources.resource_filename("rbperf", "bpf/rbperf.c")
        with open(bpf_program_path, "rb") as bpf_program:
            bpf_text = bpf_program.read()

        self.bpf = BPF(
            text=bpf_text,
            cflags=[
                f"-D__BPF_PROGRAMS_COUNT__={self.bpf_programs_count}",
                f"-D__MAX_STACKS_PER_PROGRAM__={self.max_stacks_per_program}",
                f"-DREAD_USERSPACE_ADDRESS_SPACE={int(read_userspace_address_space())}",
            ],
            usdt_contexts=self.usdt_contexts,
        )

        programs = self.bpf.get_table(b"programs")
        read_ruby_frames = self.bpf.load_func(b"read_ruby_frames", self.bpf_type())
        programs[c_int(0)] = c_int(read_ruby_frames.fd)

        self.open_perf_buffer()

    def add_version_specific_offsets(self):
        for i, (_, offset) in enumerate(offsets_for_version.items()):
            self.bpf[b"version_specific_offsets"][c_int(i)] = offset

    def add_pids(self, pids):
        for pid in pids:
            self.add_pid(pid)

    def add_pid(self, pid):
        if not process_exists(pid):
            print(f"Process with PID {pid} is not running")
            return

        rb_info = rb_thread_address(pid)
        if not rb_info:
            return

        self.pids.add(pid)

        addr, version = rb_info
        numeric_version = index_for_version(version.decode())
        if numeric_version is None:
            print(f"Ruby {version} not found, skipping")
            return

        print(f"Profiling pid: {pid} (Ruby {version.decode()}) with addr: 0x{addr:02x}")

        self.bpf[b"pid_to_rb_thread"][c_uint(pid)] = ProcessData(
            rb_frame_addr=c_ulonglong(addr), rb_version=c_int(numeric_version)
        )

    def remove_pid(self, pid):
        self.pids.remove(pid)
        del self.bpf[b"pid_to_rb_thread"][c_uint(pid)]

    def open_perf_buffer(self):
        self.bpf[b"events"].open_perf_buffer(
            self.on_event, page_cnt=self.page_count, lost_cb=self.on_lost_event
        )

    def poll_perf_one_event(self):
        self.bpf.perf_buffer_poll()
        while self.queue:
            self.process_event()

    def poll(self):
        while True:
            try:
                self.poll_perf_one_event()
            except KeyboardInterrupt:
                print("Received sigint, exiting...")
                return self.sample_handler.finish()

    def on_event(self, cpu, data, size):
        self.queue.append(self.bpf[b"events"].event(data))

    def process_event(self):
        event = self.queue.pop(0)
        stacktrace = {
            "timestamp": event.timestamp,
            # TODO: When dealing with very high-frequency events, sometimes
            # comm is garbled bytes. This needs more investigation.
            "comm": safely_decode_bytes(event.comm, "[comm failed to fetch]"),
            "pid": event.pid,
            "stack_status": event.stack_status,
            "frames": [],
        }

        for i in range(event.size):
            frame_key = event.frames[i]
            try:
                frame = self.bpf[b"id_to_stack"][c_ulong(frame_key)]
            except KeyError as e:
                self.sample_handler.process_lost_stacks(e)
                return

            method_name = frame.method_name.decode()
            path = frame.path.decode()
            lineno = frame.lineno

            stacktrace["frames"].append(
                {
                    "method_name": frame.method_name.decode(),
                    "path": frame.path.decode(),
                    "lineno": frame.lineno,
                }
            )

        self.sample_handler.process_sample(stacktrace)

    def on_lost_event(self, lost_event_count):
        self.sample_handler.process_lost_events(lost_event_count)


class RbperfPerfEvent(RubyBPFStackWalker):
    def profile(self, sample_period=0, cpu=-1):
        self.sample_handler.set_config(profile_type=rbperf_pb2.Profile.Type.PERF)

        self.bpf.attach_perf_event(
            ev_type=PerfType.SOFTWARE,
            ev_config=PerfSWConfig.CPU_CLOCK,
            fn_name=self.BPF_FUNCTION_NAME,
            sample_period=sample_period,
            sample_freq=0,
            cpu=cpu,
        )
        return self

    def bpf_type(self):
        return BPF.PERF_EVENT


class RbperfTracepoint(RubyBPFStackWalker):
    def trace(self, event):
        self.sample_handler.set_config(profile_type=rbperf_pb2.Profile.Type.TRACEPOINT)
        self.bpf.attach_tracepoint(
            tp=event, fn_name=self.BPF_FUNCTION_NAME,
        )
        return self

    def bpf_type(self):
        return BPF.TRACEPOINT


class RbperfUprobe(RubyBPFStackWalker):
    def trace(self, name, symbol):
        self.sample_handler.set_config(profile_type=rbperf_pb2.Profile.Type.UPROBE)
        for pid in self.pids:
            self.bpf.attach_uprobe(
                name=name, sym=symbol, fn_name=self.BPF_FUNCTION_NAME, pid=pid
            )
        return self

    def bpf_type(self):
        return BPF.KPROBE


class RbperfUSDT(RubyBPFStackWalker):
    def __init__(self, usdt_name, pids, *args, **kwargs):
        # TODO(javierhonduco): Check what happens if we call this more than once on the same
        # Ruby binary
        for pid in pids:
            usdt = USDT(pid=pid)
            usdt.enable_probe_or_bail(usdt_name, self.BPF_FUNCTION_NAME.decode())
            self.usdt_contexts.append(usdt)
        super().__init__(pids, *args, **kwargs)

    def trace(self):
        self.sample_handler.set_config(profile_type=rbperf_pb2.Profile.Type.USDT)
        return self

    def bpf_type(self):
        return BPF.KPROBE
