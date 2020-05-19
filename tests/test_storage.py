# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import unittest
import io

from storage import (
    CompactProtobufReader,
    CompactProtobufWriter,
    StreamingProtobufWriter,
    StreamingProtobufReader,
)
from proto import rbperf_pb2


class CompactStorageTestCase(unittest.TestCase):
    def test_can_read_write(self):
        with io.BytesIO() as f:
            profile = rbperf_pb2.Profile()
            CompactProtobufWriter(f).write_profile(profile)

            f.seek(0)
            self.assertEqual(list(CompactProtobufReader(f).read_stacks()), [])

    def test_can_read_stacks(self):
        with io.BytesIO() as f:
            frames = [
                rbperf_pb2.InternedFrame(path=0, method=1, lineno=3),
                rbperf_pb2.InternedFrame(path=2, method=3, lineno=5),
            ]
            profile = rbperf_pb2.Profile(
                stacktraces=[
                    rbperf_pb2.StackTrace(
                        timestamp=314,
                        tid=100,
                        cpu=3,
                        pid=111,
                        comm="love-ruby!",
                        stack_status=1,
                        interned_frames=frames,
                    )
                ],
                string_table={
                    0: "omg_path",
                    1: "function_1",
                    2: "lol_path",
                    3: "function_2",
                },
            )
            CompactProtobufWriter(f).write_profile(profile)

            f.seek(0)
            for stack in CompactProtobufReader(f).read_stacks():
                self.assertEqual(stack.timestamp, 314)
                self.assertEqual(stack.tid, 100)
                self.assertEqual(stack.cpu, 3)
                self.assertEqual(stack.pid, 111)
                self.assertEqual(stack.comm, "love-ruby!")
                self.assertEqual(stack.stack_status, 1)

                for frame in stack.interned_frames:
                    self.assertIn(frame, frames)

    def test_asserts_error_with_wrong_storage_type(self):
        with io.BytesIO() as f:
            profile = rbperf_pb2.Profile()
            StreamingProtobufWriter(f).write_header(profile)

            f.seek(0)

            with self.assertRaises(AssertionError):
                CompactProtobufReader(f).read_stacks()

    def test_asserts_error_with_bad_magic_string(self):
        with io.BytesIO() as f:
            profile = rbperf_pb2.Profile()
            CompactProtobufWriter(f).write_profile(profile)

            f.seek(0)
            f.write(b"z")
            f.seek(0)

            with self.assertRaises(AssertionError):
                CompactProtobufReader(f).read_stacks()


class StreamingTestCase(unittest.TestCase):
    def test_can_read_write(self):
        with io.BytesIO() as f:
            profile = rbperf_pb2.Profile()
            StreamingProtobufWriter(f).write_header(profile)

            f.seek(0)
            self.assertEqual(list(StreamingProtobufReader(f).read_stacks()), [])

    def test_can_read_stacks(self):
        with io.BytesIO() as f:
            stacks = [
                rbperf_pb2.StackTrace(
                    frames=[
                        rbperf_pb2.Frame(path="lovely_path", method="fabada", lineno=3),
                        rbperf_pb2.Frame(path="cute_path", method="tortilla", lineno=5),
                    ]
                )
            ]
            profile = rbperf_pb2.Profile()
            cpw = StreamingProtobufWriter(f)
            cpw.write_header(profile)
            for stack in stacks:
                cpw.write_stack(stack)

            f.seek(0)
            for read_stacks in StreamingProtobufReader(f).read_stacks():
                for frame in read_stacks.frames:
                    self.assertIn(frame, stacks[0].frames)

    def test_asserts_error_with_wrong_storage_type(self):
        with io.BytesIO() as f:
            profile = rbperf_pb2.Profile()
            CompactProtobufWriter(f).write_profile(profile)

            f.seek(0)

            with self.assertRaises(AssertionError):
                StreamingProtobufReader(f).read_stacks()

    def test_asserts_error_with_bad_magic_string(self):
        with io.BytesIO() as f:
            profile = rbperf_pb2.Profile()
            StreamingProtobufWriter(f).write_header(profile)

            f.seek(0)
            f.write(b"z")
            f.seek(0)

            with self.assertRaises(AssertionError):
                StreamingProtobufReader(f).read_stacks()
