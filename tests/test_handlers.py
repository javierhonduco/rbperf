# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import unittest
import io

from handlers import CompactHandler


class HandlersTestCase(unittest.TestCase):
    def test_no_frames(self):
        f = io.BytesIO()
        f.name = "in_memory_file"

        sample = {"pid": 1, "comm": "init.rb", "stack_status": 0, "frames": []}

        handler = CompactHandler(f)
        handler.process_sample(sample)
        handler.finish()

    def test_it_works(self):
        f = io.BytesIO()
        f.name = "in_memory_file"

        sample = {
            "pid": 1,
            "comm": "init.rb",
            "stack_status": 0,
            "frames": [
                {"path": "/meow", "method_name": "make_noise", "lineno": 314},
                {"path": "/woof", "method_name": "make_noise", "lineno": 404},
            ],
        }

        handler = CompactHandler(f)
        handler.process_sample(sample)
        handler.process_lost_events(300)
        handler.process_lost_stacks(sample)
        profile_stats = handler.finish()

        self.assertEqual(profile_stats.total, 1)
        self.assertEqual(profile_stats.worked_off, 1)
        self.assertEqual(profile_stats.lost, 300)
        self.assertEqual(profile_stats.incomplete, 0)
        self.assertEqual(profile_stats.lost_stacks, 1)
