# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import os
import glob
import sys
from ctypes import cast, byref, POINTER
from typing import Optional, List, Tuple

from bcc import lib, bcc_symbol_option, bcc_symbol  # type: ignore

from poke import read_ruby_version_string
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
    resolved_symbol = bcc_symbol()
    ret_val = lib.bcc_resolve_symname(
        binary_path.encode(),
        symbol.encode(),
        0x0,
        0x0,
        cast(None, POINTER(bcc_symbol_option)),  # type: ignore
        resolved_symbol,
    )
    if ret_val < 0:
        raise RuntimeError(
            f"Symbol {symbol} from library {binary_path} could not be found"
        )
    return resolved_symbol.offset


def base_process_address(pid: int) -> int:
    # TODO(javierhonduco): Make this more robust
    with open(f"/proc/{pid}/smaps", "rb") as smaps:
        first_line = smaps.readline()
    addr_str = first_line.decode().split("-")[0]
    return int(addr_str, 16)


def ruby_version(pid: int, library_path: str, start_address: int) -> Optional[bytes]:
    version_address = symbol_address(library_path, "ruby_version")
    if not version_address:
        return None
    return read_ruby_version_string(pid, start_address + version_address)


def rb_thread_address(pid: int) -> Optional[Tuple[int, bytes]]:
    dyn_linked = ruby_dynamic_linked(pid)

    if dyn_linked is None:
        path = f"/proc/{pid}/exe"
        addr = base_process_address(pid)
    else:
        path, addr = dyn_linked

    version = ruby_version(pid, path, addr)
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
