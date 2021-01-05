# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import os
import glob
import ctypes as ct
from typing import Optional, List, Tuple

from bcc import bcc_symbol_option, bcc_symbol  # type: ignore

from version_specific_config import ruby_thread_name


def is_root() -> bool:
    return os.geteuid() == 0


def max_stacks_for_kernel() -> int:
    """
    In newer kernels we can have up to 1 million BPF instructions,
    before there was a limit of 4096

    These numbers were obtained empirically in my machine running
    5.6.8 and in Ubuntu 18.04 (Bionic), the lastest GitHub actions
    supports, which runs 5.3.0
    """
    major, minor = map(int, os.uname().release.split(".")[:2])
    if (major, minor) > (5, 3):
        return 30
    else:
        return 15


def read_userspace_address_space() -> bool:
    """
    Naive check to see if `read_userspace_address_space` & friends
    are supported
    """
    major, minor = map(int, os.uname().release.split(".")[:2])
    return (major, minor) >= (5, 4)


def ruby_dynamic_linked(pid: int) -> Optional[Tuple[str, int]]:
    with open(f"/proc/{pid}/smaps", "rb") as smaps:
        for line in smaps.readlines():
            # TODO(javierhonduco): Make this more robust
            if b"libruby" in line:
                library_path = line.decode().split(" ")[-1].strip()
                map_start_addrs = line.decode().split("-")[0].strip()
                return library_path, int(map_start_addrs, 16)
    return None


def symbol_address(binary_path: str, symbol: str) -> Optional[int]:
    result = None
    STT_OBJECT = 1

    bcc = ct.CDLL("libbcc.so.0", use_errno=True)

    callback_type = ct.CFUNCTYPE(
        ct.c_int, ct.c_char_p, ct.c_ulonglong, ct.c_ulonglong, ct.c_void_p
    )
    bcc.bcc_elf_foreach_sym.restype = ct.c_int
    bcc.bcc_elf_foreach_sym.argtypes = [
        ct.c_char_p,
        callback_type,
        ct.POINTER(bcc_symbol_option),
        ct.c_void_p,
    ]

    symbol_bytes = symbol.encode()

    def exact_match(name, addr, payload, _):
        nonlocal result
        if name == symbol_bytes:
            result = addr
            return -1
        return 0

    ops = bcc_symbol_option()
    ops.use_debug_file = 0
    ops.check_debug_file_crc = 0
    ops.lazy_symbolize = 1
    ops.use_symbol_type = 1 << STT_OBJECT

    ret_val = bcc.bcc_elf_foreach_sym(
        binary_path.encode(),
        callback_type(exact_match),
        ct.byref(ops),
        None,  # We don't use any cookies
    )
    if ret_val < 0:
        raise RuntimeError(
            f"Symbol {symbol} from library {binary_path} could not be found"
        )

    return result


def base_process_address(pid: int) -> int:
    # TODO(javierhonduco): Make this more robust
    with open(f"/proc/{pid}/smaps", "rb") as smaps:
        first_line = smaps.readline()
    addr_str = first_line.decode().split("-")[0]
    return int(addr_str, 16)


def ruby_version(pid: int, binary_path: str) -> Optional[bytes]:
    version_address = symbol_address(binary_path, "ruby_version")
    if not version_address:
        return None

    # Read the Ruby version off the .rodata section
    with open(binary_path, "rb") as executable:
        executable.seek(version_address)
        return executable.read(5)


def rb_thread_address(pid: int) -> Optional[Tuple[int, bytes]]:
    dyn_linked = ruby_dynamic_linked(pid)

    if dyn_linked is None:
        path = f"/proc/{pid}/exe"
        addr = base_process_address(pid)
    else:
        path, addr = dyn_linked

    version = ruby_version(pid, path)
    if not version:
        print(f"not a Ruby process (path: {path}, pid: {pid})")
        return None

    rb_current_thread_name = ruby_thread_name(version.decode())
    sym_addr = symbol_address(path, rb_current_thread_name)
    if sym_addr:
        return addr + sym_addr, version
    else:
        raise RuntimeError(f"Could not find the thread address for PID={pid}")


def all_pids(maybe_ruby: bool = True) -> List[int]:
    pids = []
    for p in glob.glob("/proc/[0-9]*"):
        if maybe_ruby:
            try:
                # This can cause a priority inversion in some circumstances
                with open(f"{p}/cmdline") as cmdline:
                    if "ruby" in cmdline.read():
                        pids.append(int(p.replace("/proc/", "").replace("/", "")))
            except FileNotFoundError:
                # There's a race condition between listing and opening
                pass
        else:
            pids.append(int(p.replace("/proc/", "").replace("/", "")))

    return pids


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def safely_decode_bytes(content: bytes, placeholder: str) -> str:
    try:
        return content.decode()
    except UnicodeDecodeError:
        return placeholder
