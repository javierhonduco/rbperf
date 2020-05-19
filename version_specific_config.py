# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from typing import Dict, Tuple, Optional
from ctypes import Structure, c_int


class VersionConfig(Structure):
    _fields_ = [
        ("vm_offset", c_int),
        ("vm_size_offset", c_int),
        ("control_frame_t_sizeof", c_int),
        ("cfp_offset", c_int),
        ("label_offset", c_int),
        ("path_flavour", c_int),
        ("line_info_size_offset", c_int),
        ("line_info_table_offset", c_int),
        ("lineno_offset", c_int),
    ]


offsets_for_version: Dict[Tuple[str, ...], VersionConfig] = {}

offsets_for_version[("2.4.4",)] = VersionConfig(
    vm_offset=c_int(0x20),  # offsetof(struct rb_thread_struct, stack)
    vm_size_offset=c_int(0x28),  # offsetof(struct rb_thread_struct, stack_size)
    control_frame_t_sizeof=c_int(0x30),  # sizeof(rb_control_frame_t)
    cfp_offset=c_int(0x30),  # offsetof(struct rb_execution_context_struct, cfp)
    label_offset=c_int(0x18),  # offsetof(struct rb_iseq_location_struct, label)
    path_flavour=c_int(0),
    line_info_size_offset=c_int(0xC0),  # offsetof(struct rb_iseq_constant_body, line_info_size)
    line_info_table_offset=c_int(0x68),  # offsetof(struct rb_iseq_constant_body, line_info_table)
    lineno_offset=c_int(0x4),  # offsetof(struct rb_iseq_constant_body, line_info_table)
)

offsets_for_version[("2.5.0", "2.5.3", "2.5.7", "2.5.8")] = VersionConfig(
    vm_offset=c_int(0x0),  # offsetof(struct rb_execution_context_struct, vm_stack)
    vm_size_offset=c_int(0x8),  # offsetof(struct rb_execution_context_struct, vm_stack_size)
    control_frame_t_sizeof=c_int(0x30),  # sizeof(rb_control_frame_t)
    cfp_offset=c_int(0x10),  # offsetof(struct rb_execution_context_struct, cfp)
    label_offset=c_int(0x10),  # offsetof(struct rb_iseq_location_struct, label)
    path_flavour=c_int(1),
    line_info_size_offset=c_int(0xC8),  # offsetof(struct rb_iseq_constant_body, insns_info_size)
    line_info_table_offset=c_int(0x70),  # offsetof(struct rb_iseq_constant_body, insns_info)
    lineno_offset=c_int(0x04),  # offsetof(struct iseq_insn_info_entry, line_no)
)
offsets_for_version[("2.6.3", "2.6.4", "2.6.5", "2.6.6", "2.7.1")] = VersionConfig(
    vm_offset=c_int(0x0),  # offsetof(struct rb_execution_context_struct, vm_stack)
    vm_size_offset=c_int(0x8),  # offsetof(struct rb_execution_context_struct, vm_stack_size)
    control_frame_t_sizeof=c_int(0x38),  # sizeof(rb_control_frame_t)
    cfp_offset=c_int(0x10),  # offsetof(struct rb_execution_context_struct, cfp)
    label_offset=c_int(0x10),  # offsetof(struct rb_iseq_location_struct, label)
    path_flavour=c_int(1),
    line_info_size_offset=c_int(0x78 + 0x10),  # offsetof(struct rb_iseq_constant_body, insns_info) + offsetof(struct iseq_insn_info, size)
    line_info_table_offset=c_int(0x78),  # offsetof(struct rb_iseq_constant_body, insns_info)
    lineno_offset=c_int(0x0),  # offsetof(struct iseq_insn_info_entry, line_no)
)


def index_for_version(version: str) -> Optional[int]:
    for i, (versions, _) in enumerate(offsets_for_version.items()):
        if version in versions:
            return i

    return None


def ruby_thread_name(version: str) -> str:
    if version.startswith("2.5") or version.startswith("2.6") or version.startswith("2.7"):
        return "ruby_current_execution_context_ptr"
    return "ruby_current_thread"
