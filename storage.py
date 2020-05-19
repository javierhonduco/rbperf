# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from proto import rbperf_pb2
import struct

MAGIC_STRING = b"rbperf"


class CompactProtobufWriter:
    def __init__(self, file_object):
        self.file = file_object
        self._write_magic_string()
        self._write_storage_type()

    def write_profile(self, profile):
        self.file.write(profile.SerializeToString())

    def _write_magic_string(self):
        self.file.write(MAGIC_STRING)

    def _write_storage_type(self):
        self.file.write(struct.pack("<H", rbperf_pb2.StorageType.COMPACT))


class CompactProtobufReader:
    def __init__(self, file_object):
        self.file = file_object
        self._verify_magic_string()
        self._verify_storage_type()

    def read_stacks(self):
        self.profile = self._read_profile()
        for stack in self.profile.stacktraces:
            stack_trace = rbperf_pb2.StackTrace(
                timestamp=stack.timestamp,
                tid=stack.tid,
                cpu=stack.cpu,
                pid=stack.pid,
                comm=stack.comm,
                stack_status=stack.stack_status,
            )
            for frame in stack.interned_frames:
                cur_frame = rbperf_pb2.Frame()
                cur_frame.path = self.symbol_for_id(frame.path)
                cur_frame.method = self.symbol_for_id(frame.method)
                cur_frame.lineno = frame.lineno

                stack_trace.frames.append(cur_frame)
            yield stack_trace

    def symbol_for_id(self, id_):
        return self.profile.string_table[id_]

    def _verify_magic_string(self):
        assert self.file.read(len(MAGIC_STRING)) == MAGIC_STRING

    def _verify_storage_type(self):
        storage_type_bytes = self.file.read(2)
        assert (
            struct.unpack("<H", storage_type_bytes)[0] == rbperf_pb2.StorageType.COMPACT
        )

    def _read_profile(self):
        profile_bytes = self.file.read()

        profile = rbperf_pb2.Profile()
        profile.ParseFromString(profile_bytes)
        return profile


class StreamingProtobufWriter:
    def __init__(self, file_object):
        self.file = file_object
        self._write_magic_string()
        self._write_storage_type()

    def write_header(self, header):
        self.file.write(struct.pack("<I", header.ByteSize()))
        self.file.write(header.SerializeToString())

    def write_stack(self, stack):
        self.file.write(struct.pack("<I", stack.ByteSize()))
        self.file.write(stack.SerializeToString())

    def _write_magic_string(self):
        self.file.write(MAGIC_STRING)

    def _write_storage_type(self):
        self.file.write(struct.pack("<H", rbperf_pb2.StorageType.STREAMING))


class StreamingProtobufReader:
    def __init__(self, file_object):
        self.file = file_object
        self._verify_magic_string()
        self._verify_storage_type()
        self.header = self._read_header()

    def read_header(self):
        return self.header

    def read_stacks(self):
        while True:
            stack_trace_size_bytes = self.file.read(4)
            if stack_trace_size_bytes == b"":
                return

            stack_trace_size = struct.unpack("<I", stack_trace_size_bytes)[0]
            stack_trace_bytes = self.file.read(stack_trace_size)
            stack_trace = rbperf_pb2.StackTrace()
            stack_trace.ParseFromString(stack_trace_bytes)
            yield stack_trace

    def _verify_magic_string(self):
        assert self.file.read(len(MAGIC_STRING)) == MAGIC_STRING

    def _verify_storage_type(self):
        storage_type_bytes = self.file.read(2)
        assert (
            struct.unpack("<H", storage_type_bytes)[0]
            == rbperf_pb2.StorageType.STREAMING
        )

    def _read_header(self):
        header_size = struct.unpack("<I", self.file.read(4))[0]
        header_bytes = self.file.read(header_size)

        header = rbperf_pb2.Profile()
        header.ParseFromString(header_bytes)
        return header
