# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import sys
import subprocess
import os
import time
import unittest

# TODO(javierhonduco): Rethink vendorised bcc
parent_dir = os.path.abspath(os.path.dirname(__file__))
vendor_dir = os.path.join(parent_dir, "../vendor")
sys.path.insert(0, vendor_dir)

from rbperf import RbperfPerfEvent, RbperfTracepoint
from utils import is_root

if not is_root():
    print("You need to be root to load BPF programs")
    sys.exit(1)


# Unfortunately CI's Kernel does not support 1M instructions
MAX_STACKS = 15

DEFAULT_RUBY_BINARY = "ruby-2.6.3"
EVERY_MILLION_EVENTS = 10 ** 6


def spawn_test_ruby(version, testcase):
    process = subprocess.Popen(
        [f"tests/rubies/{version}", "--disable-gems", testcase],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    # Block until the program prints something. We do this to know
    # when it's all set up by the OS, such as the process' memory
    # pages
    process.stdout.readline()
    return process


class TestHandler:
    # TODO(javierhonduco): This handler is not complete, so a missing
    # event handling will make it raise. Let's change this and assert
    # on our those stats.
    #
    # These tests are flaky due to that, but I can't think of a way
    # around this :(
    def __init__(self):
        pass

    def set_config(self, **kwargs):
        pass

    def process_sample(self, stacktrace):
        self.stacktrace = stacktrace


handler = TestHandler()
rbprof = RbperfTracepoint(pids=[], sample_handler=handler, max_stacks=MAX_STACKS).trace(
    b"syscalls:sys_enter_openat"
)


class TestStackWalker(unittest.TestCase):
    def setUp(self):
        # TODO(javierhonduco): Clear up BCC data as well?
        handler.stacktrace = None

    def test_lineno_ruby_2_4(self):
        self._generate_event("ruby-2.4.4", "tests/ruby_programs/small_stack.rb")

        first_frame = handler.stacktrace["frames"][0]
        last_frame = handler.stacktrace["frames"][-1]

        self.assertEqual(first_frame["lineno"], 25)
        self.assertEqual(last_frame["lineno"], 2)

    def test_lineno_rest(self):
        """
        Line numbers are not accurate in these Ruby versions but let's test them
        anyways to make sure we don't regress
        """
        ruby_versions = [
            # TODO(javierhonduco): Line number for Ruby 2.5 are either broken on our side
            # or use the table that we are not implementing
            # "ruby-2.5.0",
            # "ruby-2.5.7",
            # "ruby-2.5.8",
            "ruby-2.6.3",
            "ruby-2.6.6",
            "ruby-2.7.1",
        ]
        for ruby_version in ruby_versions:
            with self.subTest(msg=f"testing ruby: {ruby_version}"):
                self._generate_event(ruby_version, "tests/ruby_programs/small_stack.rb")

                first_frame = handler.stacktrace["frames"][0]
                last_frame = handler.stacktrace["frames"][-1]

                self.assertEqual(first_frame["lineno"], 25)
                self.assertEqual(last_frame["lineno"], 3)  # This is in reality line 2

    def test_stacks_for_different_each_ruby_version(self):
        ruby_versions = [
            "ruby-2.4.4",
            "ruby-2.5.0",
            "ruby-2.5.7",
            "ruby-2.5.8",
            "ruby-2.6.3",
            "ruby-2.6.6",
            "ruby-2.7.1",
        ]
        for ruby_version in ruby_versions:
            with self.subTest(msg=f"Testing Ruby: {ruby_version}"):
                self._test_small_case(ruby_version)

    def test_large_stack(self):
        self._generate_event(DEFAULT_RUBY_BINARY, "tests/ruby_programs/large_stack.rb")

        stacktrace = handler.stacktrace

        pid = stacktrace["pid"]
        comm = stacktrace["comm"]

        self.assertEqual(stacktrace["stack_status"], 0)  # stack is complete
        self.assertEqual(len(stacktrace["frames"]), 36)

        first_frame = stacktrace["frames"][0]
        last_frame = stacktrace["frames"][-1]

        self.assertEqual(first_frame["path"], "tests/ruby_programs/large_stack.rb")
        self.assertEqual(first_frame["method_name"], "<main>")

        self.assertEqual(last_frame["path"], "tests/ruby_programs/large_stack.rb")
        self.assertEqual(last_frame["method_name"], "infinite_loop")

    def test_stack_too_large(self):
        self._generate_event(DEFAULT_RUBY_BINARY, "tests/ruby_programs/huge_stack.rb")

        stacktrace = handler.stacktrace

        pid = stacktrace["pid"]
        comm = stacktrace["comm"]

        self.assertEqual(stacktrace["stack_status"], 1)  # stack is incomplete
        # as we can't collect all the frames, if there's any C frame in between this numbe might be slightly different
        self.assertGreater(len(stacktrace["frames"]), 43)
        first_frame = stacktrace["frames"][0]
        rest_frames = stacktrace["frames"][2:70]

        self.assertEqual(first_frame["path"], "tests/ruby_programs/huge_stack.rb")
        self.assertEqual(first_frame["method_name"], "<main>")

        self.assertEqual(
            [frame["path"] for frame in rest_frames],
            ["tests/ruby_programs/huge_stack.rb"] * 42,
        )
        expected_method_names = [f"a{i}" for i in range(1, 43)]
        self.assertEqual(
            [frame["method_name"] for frame in rest_frames], expected_method_names
        )

    def test_global_data_is_properly_cleared(self):
        self._generate_event(DEFAULT_RUBY_BINARY, "tests/ruby_programs/huge_stack.rb")
        self.assertIsNotNone(handler.stacktrace)
        # small program
        self._test_small_case(DEFAULT_RUBY_BINARY)

    def test_process_metadata(self):
        # self._generate_event(DEFAULT_RUBY_BINARY, "tests/ruby_programs/small_stack")
        # assert PID, TID, COMM, etc
        pass

    def _generate_event(self, version, testcase):
        p = spawn_test_ruby(version, testcase)
        rbprof.add_pid(p.pid)
        os.kill(p.pid, 10)
        rbprof.poll_perf_one_event()
        p.kill()
        p.wait()
        rbprof.remove_pid(p.pid)
        p.stdout.close()

    def _test_small_case(self, version):
        self._generate_event(version, "tests/ruby_programs/small_stack.rb")

        stacktrace = handler.stacktrace

        pid = stacktrace["pid"]
        comm = stacktrace["comm"]

        self.assertEqual(stacktrace["stack_status"], 0)  # stack is complete
        self.assertEqual(len(stacktrace["frames"]), 6)

        first_frame = stacktrace["frames"][0]
        last_frame = stacktrace["frames"][-1]

        self.assertEqual(first_frame["path"], "tests/ruby_programs/small_stack.rb")
        self.assertEqual(first_frame["method_name"], "<main>")

        self.assertEqual(last_frame["path"], "tests/ruby_programs/small_stack.rb")
        self.assertEqual(last_frame["method_name"], "infinite_loop")


class TestIncreasedTailCallsTestCase(unittest.TestCase):
    def test_stack_too_large_works(self):
        handler = TestHandler()
        self.rbprof = RbperfTracepoint(
            pids=[], sample_handler=handler, bpf_programs_count=20
        ).trace(b"syscalls:sys_enter_openat")

        self._generate_event(DEFAULT_RUBY_BINARY, "tests/ruby_programs/huge_stack.rb")

        stacktrace = handler.stacktrace
        pid = stacktrace["pid"]
        comm = stacktrace["comm"]

        self.assertEqual(stacktrace["stack_status"], 0)  # stack is complete
        frame_count = len(stacktrace["frames"])

        first_frame = stacktrace["frames"][0]
        rest_frames = stacktrace["frames"][2 : frame_count - 1]
        last_frame = stacktrace["frames"][-1]

        self.assertEqual(first_frame["path"], "tests/ruby_programs/huge_stack.rb")
        self.assertEqual(first_frame["method_name"], "<main>")

        self.assertEqual(
            [frame["path"] for frame in rest_frames],
            ["tests/ruby_programs/huge_stack.rb"] * (frame_count - 3),
        )
        expected_method_names = [f"a{i}" for i in range(1, frame_count - 2)]
        self.assertEqual(
            [frame["method_name"] for frame in rest_frames], expected_method_names
        )

        self.assertEqual(last_frame["path"], "tests/ruby_programs/huge_stack.rb")
        self.assertEqual(last_frame["method_name"], "infinite_loop")

    def _generate_event(self, version, testcase):
        p = spawn_test_ruby(version, testcase)
        self.rbprof.add_pid(p.pid)
        os.kill(p.pid, 10)
        self.rbprof.poll_perf_one_event()
        p.kill()
        p.wait()
        self.rbprof.remove_pid(p.pid)
        p.stdout.close()


class TestProfiler(unittest.TestCase):
    def test_profiler_works(self):
        handler = TestHandler()
        self.handler = handler
        rbprof = RbperfPerfEvent(
            pids=[], sample_handler=handler, max_stacks=MAX_STACKS
        ).profile(sample_period=EVERY_MILLION_EVENTS)

        p = spawn_test_ruby(DEFAULT_RUBY_BINARY, "tests/ruby_programs/sleepy.rb")
        rbprof.add_pid(p.pid)

        for i in range(10):
            rbprof.poll_perf_one_event()
            self._run_assertions()

        rbprof.remove_pid(p.pid)
        p.stdout.close()
        p.kill()
        p.wait()

    def _run_assertions(self):
        stacktrace = self.handler.stacktrace

        pid = stacktrace["pid"]
        comm = stacktrace["comm"]

        self.assertEqual(stacktrace["stack_status"], 0)  # stack is complete
        self.assertEqual(len(stacktrace["frames"]), 5)

        first_frame = stacktrace["frames"][0]
        last_frame = stacktrace["frames"][-1]

        self.assertEqual(first_frame["path"], "tests/ruby_programs/sleepy.rb")
        self.assertEqual(first_frame["method_name"], "<main>")

        self.assertEqual(last_frame["path"], "tests/ruby_programs/sleepy.rb")
        self.assertEqual(last_frame["method_name"], "infinite_loop")


if __name__ == "__main__":
    unittest.main()
