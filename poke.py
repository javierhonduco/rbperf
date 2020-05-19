# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import ctypes
from ctypes import (
    c_ssize_t,
    c_int,
    Structure,
    c_size_t,
    c_void_p,
    c_ulong,
    POINTER,
    cast,
    c_char,
)

"""
A process_vm_readv(2) wrapper to read from the profiled process'
memory. We use it to read the Ruby version.

We need to do this because each Ruby version might have slightly
different offsets and struct sizes, etc.

See version_specific_config.py for more details.
"""


class IOVec(Structure):
    _fields_ = [("iov_base", c_void_p), ("iov_len", c_size_t)]


libc = ctypes.CDLL(None, use_errno=True)  # type: ignore
process_vm_readv = libc.process_vm_readv
process_vm_readv.restype = c_ssize_t
process_vm_readv.argtypes = (
    c_int,
    POINTER(IOVec),
    c_ulong,
    POINTER(IOVec),
    c_ulong,
    c_ulong,
)


def process_vm_readv_wrapper(pid: int, address: int, length: int) -> c_void_p:
    local_iov = IOVec()
    local_iov.iov_base = cast(ctypes.create_string_buffer(b"", length), c_void_p)
    local_iov.iov_len = length

    remote_iov = IOVec()
    remote_iov.iov_base = c_void_p(address)
    remote_iov.iov_len = length

    ret_val = process_vm_readv(pid, (local_iov), 1, (remote_iov), 1, 0)
    if ret_val == -1 or ret_val < length:
        raise OSError(ctypes.get_errno(), f"process_vm_readv failed ret: {ret_val}")

    return local_iov.iov_base


def read_cstring(address: c_void_p) -> bytes:
    chars = []

    for char in cast(address, POINTER(c_char)):  # type: ignore
        if char == b"\x00":
            break
        chars.append(char)

    return b"".join(chars)


def read_ruby_version_string(pid: int, address: int) -> bytes:
    return read_cstring(process_vm_readv_wrapper(pid=pid, address=address, length=10))
