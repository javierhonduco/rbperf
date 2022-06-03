use crate::RubyVersionOffsets;

pub const ruby_2_6_0: RubyVersionOffsets = RubyVersionOffsets {
    major_version: 2,
    minor_version: 6,
    patch_version: 0,
    vm_offset: 0x0,
    vm_size_offset: 0x8,
    control_frame_t_sizeof: 0x38,
    cfp_offset: 0x10,
    label_offset: 0x10,
    path_flavour: 1,
    line_info_size_offset: 0x78 + 0x10,
    line_info_table_offset: 0x78,
    lineno_offset: 0x0,
};

pub const ruby_2_6_3: RubyVersionOffsets = RubyVersionOffsets {
    major_version: 2,
    minor_version: 6,
    patch_version: 3,
    ..ruby_2_6_0
};

pub const ruby_2_7_0: RubyVersionOffsets = RubyVersionOffsets {
    major_version: 2,
    minor_version: 7,
    patch_version: 0,
    ..ruby_2_6_0
};

pub const ruby_2_7_1: RubyVersionOffsets = RubyVersionOffsets {
    major_version: 2,
    minor_version: 7,
    patch_version: 1,
    ..ruby_2_6_0
};

pub const ruby_2_7_4: RubyVersionOffsets = RubyVersionOffsets {
    major_version: 2,
    minor_version: 7,
    patch_version: 4,
    ..ruby_2_6_0
};

pub const ruby_3_0_0: RubyVersionOffsets = RubyVersionOffsets {
    major_version: 3,
    minor_version: 0,
    patch_version: 0,
    vm_offset: 0x0,
    vm_size_offset: 0x8,
    control_frame_t_sizeof: 0x38,
    cfp_offset: 0x10,
    label_offset: 0x10,
    path_flavour: 1,
    line_info_size_offset: 0x78 + 0x10,
    line_info_table_offset: 0x78,
    lineno_offset: 0x0,
};

pub const ruby_3_0_4: RubyVersionOffsets = RubyVersionOffsets {
    major_version: 3,
    minor_version: 0,
    patch_version: 4,
    ..ruby_3_0_0
};

pub const ruby_3_1_2: RubyVersionOffsets = RubyVersionOffsets {
    major_version: 3,
    minor_version: 1,
    patch_version: 2,
    ..ruby_3_0_0
};