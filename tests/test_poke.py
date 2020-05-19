# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import unittest
import errno

from poke import process_vm_readv_wrapper


class ProcessVmReadvTestCase(unittest.TestCase):
    def test_handles_errno(self):
        with self.assertRaises(OSError) as e:
            process_vm_readv_wrapper(0, 0x0, 4)
        self.assertEqual(e.exception.errno, errno.ESRCH)  # no such process
