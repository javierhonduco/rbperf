# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import datetime
import queue
import threading
import os
import time
from dataclasses import dataclass

from proto import rbperf_pb2
from storage import StreamingProtobufWriter, CompactProtobufWriter


@dataclass(frozen=True)
class HandlerInfo:
    lost: int
    total: int
    incomplete: int
    lost_stacks: int
    worked_off: int
    filename: str

    def __repr__(self):
        return (
            f"Processed {self.total} events, lost {self.lost} events, lost stacks {self.lost_stacks}, "
            f"incomplete: {self.incomplete}, written: {self.worked_off}"
        )


class CompactHandler:
    def __init__(self, file_object=None):
        self.lost = 0
        self.total = 0
        self.incomplete = 0
        self.lost_stacks = 0
        self.worked_off = 0

        self.stacks = {}
        self.queue = queue.Queue()

        self.symbol_to_id = {}
        self.unique_symbol_count = 0

        self.running = True
        self.thread = threading.Thread(target=self.worker, daemon=True)
        self.thread.start()

        if file_object:
            self.file = file_object
        else:
            date = datetime.datetime.now().replace(microsecond=0).isoformat()
            self.file = open(f"rbperf-{date}.data", "wb")

        self.proto = CompactProtobufWriter(self.file)

        hostname, kernel = os.uname()[1:3]
        self.profile = rbperf_pb2.Profile(
            created_at=int(time.time()), hostname=hostname, kernel_string=kernel,
        )

    def set_config(self, profile_type):
        self.profile.type = profile_type

    def process_sample(self, stacktrace):
        self.total += 1
        self.queue.put(stacktrace)

    def worker(self):
        while self.running:
            try:
                stacktrace = self.queue.get(timeout=0.1)
            except queue.Empty:
                continue
            pid = stacktrace["pid"]
            comm = stacktrace["comm"]
            stack_status = stacktrace["stack_status"]

            if stack_status == 1:
                self.incomplete += 1

            stack = rbperf_pb2.StackTrace(
                tid=0,
                cpu=0,
                comm=comm,
                pid=pid,
                stack_status=rbperf_pb2.StackTrace.StackStatus.Name(stack_status),
            )
            stack.interned_frames.extend(
                [
                    rbperf_pb2.InternedFrame(
                        method=self.get_symbol_id(frame["method_name"]),
                        path=self.get_symbol_id(frame["path"]),
                        lineno=frame["lineno"],
                    )
                    for frame in stacktrace["frames"]
                ]
            )
            self.profile.stacktraces.append(stack)
            self.worked_off += 1
            self.queue.task_done()

    def get_symbol_id(self, symbol):
        if symbol in self.symbol_to_id:
            # can be a set?
            return self.symbol_to_id[symbol]
        else:
            self.unique_symbol_count += 1
            symbol_id = self.unique_symbol_count
            self.symbol_to_id[symbol] = symbol_id
            return symbol_id

    def process_lost_stacks(self, exception):
        self.lost_stacks += 1

    def process_lost_events(self, count):
        self.lost += count

    def fill_string_table(self):
        for symbol, id_ in self.symbol_to_id.items():
            self.profile.string_table[id_] = symbol

    def finish(self):
        try:
            self.running = False
            self.thread.join()
            self.fill_string_table()
            self.proto.write_profile(self.profile)
        finally:
            self.file.close()
            return HandlerInfo(
                lost=self.lost,
                total=self.total,
                incomplete=self.incomplete,
                lost_stacks=self.lost_stacks,
                worked_off=self.worked_off,
                filename=self.file.name,
            )


class StreamingHandler:
    """
    In cases where we want to profile a very high frequency event or
    profile over long periods of time, storing all the samples in memory
    and writing everything at once to disk might not be ideal.

    This handler writes stacks in a "streaming" fashion: It writes an
    incomplete Profile message, which lacks from the stacks or the
    symbol table for strings, and instead appends StackTrace frames
    to the file, prefixed by their size in bytes. See storage.py for
    the implementation.

    Note that this format is less efficient storage-wise as we don't
    de-duplicate strings.

    TODO(javierhonduco): we could maybe compress the file
    """

    def __init__(self, file_object=None):
        self.lost = 0
        self.total = 0
        self.incomplete = 0
        self.lost_stacks = 0
        self.worked_off = 0

        self.stacks = {}
        self.queue = queue.Queue()
        self.running = True

        """
        We should process the event as soon as we can so we allow
        the next perf event callback to run, otherwise the chances
        of losing events increase.

        In the other handlers, performance is not a concern as acute
        as it's here due to the Protobuf object allocations and
        the disk IO during the writes.
        """
        self.thread = threading.Thread(target=self.worker, daemon=True)
        self.thread.start()

        if file_object:
            self.file = file_object
        else:
            date = datetime.datetime.now().replace(microsecond=0).isoformat()
            self.file = open(f"rbperf-{date}.data", "wb")

        self.proto = StreamingProtobufWriter(self.file)

        hostname, kernel = os.uname()[1:3]
        self.profile = rbperf_pb2.Profile(
            created_at=int(time.time()), hostname=hostname, kernel_string=kernel,
        )

    def set_config(self, profile_type):
        self.profile.type = profile_type
        self.proto.write_header(self.profile)

    def process_sample(self, stacktrace):
        self.total += 1
        self.queue.put(stacktrace)

    def worker(self):
        while self.running:
            try:
                stacktrace = self.queue.get(timeout=0.1)
            except queue.Empty:
                continue
            stack_status = stacktrace["stack_status"]

            if stack_status == 1:
                self.incomplete += 1

            stack = rbperf_pb2.StackTrace(
                timestamp=stacktrace["timestamp"],
                tid=0,
                cpu=0,
                pid=stacktrace["pid"],
                comm=stacktrace["comm"],
                stack_status=rbperf_pb2.StackTrace.StackStatus.Name(stack_status),
            )
            stack.frames.extend(
                [
                    rbperf_pb2.Frame(
                        method=frame["method_name"],
                        path=frame["path"],
                        lineno=frame["lineno"],
                    )
                    for frame in stacktrace["frames"]
                ]
            )
            self.proto.write_stack(stack)
            self.worked_off += 1
            self.queue.task_done()

    def process_lost_stacks(self, exception):
        self.lost_stacks += 1

    def process_lost_events(self, count):
        self.lost += count

    def finish(self):
        try:
            self.running = False
            self.thread.join()
        finally:
            self.file.close()
            return HandlerInfo(
                lost=self.lost,
                total=self.total,
                incomplete=self.incomplete,
                lost_stacks=self.lost_stacks,
                worked_off=self.worked_off,
                filename=self.file.name,
            )
