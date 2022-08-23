use memoffset::offset_of;
use rbperf::RubyVersionOffsets;
use std::fs::File;
use std::io::Write;
use std::mem::size_of;

fn dump_ruby_structs_ruby_2_6_0() {
    let vm_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_6_0::rb_execution_context_struct,
        vm_stack
    ) as i32;

    let vm_size_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_6_0::rb_execution_context_struct,
        vm_stack_size
    ) as i32;

    let control_frame_t_sizeof: i32 =
        size_of::<rbspy_ruby_structs::ruby_2_6_0::rb_control_frame_struct>() as i32;

    let cfp_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_6_0::rb_execution_context_struct,
        cfp
    ) as i32;

    let label_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_6_0::rb_iseq_location_struct,
        label
    ) as i32;

    let line_info_table_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_6_0::rb_iseq_constant_body,
        insns_info
    ) as i32;

    let line_info_size_offset: i32 = line_info_table_offset
        + (offset_of!(
            rbspy_ruby_structs::ruby_2_6_0::rb_iseq_constant_body_iseq_insn_info,
            size
        ) as i32);

    let main_thread_offset: i32 =
        offset_of!(rbspy_ruby_structs::ruby_2_6_0::rb_vm_struct, main_thread) as i32;

    let ruby_2_6_0_offsets = RubyVersionOffsets {
        major_version: 2,
        minor_version: 6,
        patch_version: 0,
        vm_offset,
        vm_size_offset,
        control_frame_t_sizeof,
        cfp_offset,
        label_offset,
        path_flavour: 1,
        line_info_size_offset,
        line_info_table_offset,
        lineno_offset: 0,
        main_thread_offset,
        ec_offset: 32,
    };

    let yaml = serde_yaml::to_string(&ruby_2_6_0_offsets).unwrap();

    File::create("src/ruby_versions/ruby_2_6_0.yaml")
        .unwrap()
        .write_all(yaml.as_bytes())
        .unwrap();
}

fn dump_ruby_structs_ruby_2_6_3() {
    let vm_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_6_3::rb_execution_context_struct,
        vm_stack
    ) as i32;

    let vm_size_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_6_3::rb_execution_context_struct,
        vm_stack_size
    ) as i32;

    let control_frame_t_sizeof: i32 =
        size_of::<rbspy_ruby_structs::ruby_2_6_3::rb_control_frame_struct>() as i32;

    let cfp_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_6_3::rb_execution_context_struct,
        cfp
    ) as i32;

    let label_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_6_3::rb_iseq_location_struct,
        label
    ) as i32;

    let line_info_table_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_6_3::rb_iseq_constant_body,
        insns_info
    ) as i32;

    let line_info_size_offset: i32 = line_info_table_offset
        + (offset_of!(
            rbspy_ruby_structs::ruby_2_6_3::rb_iseq_constant_body_iseq_insn_info,
            size
        ) as i32);

    let main_thread_offset: i32 =
        offset_of!(rbspy_ruby_structs::ruby_2_6_3::rb_vm_struct, main_thread) as i32;

    let ruby_2_6_0_offsets = RubyVersionOffsets {
        major_version: 2,
        minor_version: 6,
        patch_version: 3,
        vm_offset,
        vm_size_offset,
        control_frame_t_sizeof,
        cfp_offset,
        label_offset,
        path_flavour: 1,
        line_info_size_offset,
        line_info_table_offset,
        lineno_offset: 0,
        main_thread_offset,
        ec_offset: 32,
    };

    let yaml = serde_yaml::to_string(&ruby_2_6_0_offsets).unwrap();

    File::create("src/ruby_versions/ruby_2_6_3.yaml")
        .unwrap()
        .write_all(yaml.as_bytes())
        .unwrap();
}

fn dump_ruby_structs_ruby_2_7_1() {
    let vm_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_1::rb_execution_context_struct,
        vm_stack
    ) as i32;

    let vm_size_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_1::rb_execution_context_struct,
        vm_stack_size
    ) as i32;

    let control_frame_t_sizeof: i32 =
        size_of::<rbspy_ruby_structs::ruby_2_7_1::rb_control_frame_struct>() as i32;

    let cfp_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_1::rb_execution_context_struct,
        cfp
    ) as i32;

    let label_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_1::rb_iseq_location_struct,
        label
    ) as i32;

    let line_info_table_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_1::rb_iseq_constant_body,
        insns_info
    ) as i32;

    let line_info_size_offset: i32 = line_info_table_offset
        + (offset_of!(
            rbspy_ruby_structs::ruby_2_7_1::rb_iseq_constant_body_iseq_insn_info,
            size
        ) as i32);

    let main_thread_offset: i32 =
        offset_of!(rbspy_ruby_structs::ruby_2_7_1::rb_vm_struct, main_thread) as i32;

    let ruby_2_7_1_offsets = RubyVersionOffsets {
        major_version: 2,
        minor_version: 7,
        patch_version: 1,
        vm_offset,
        vm_size_offset,
        control_frame_t_sizeof,
        cfp_offset,
        label_offset,
        path_flavour: 1,
        line_info_size_offset,
        line_info_table_offset,
        lineno_offset: 0,
        main_thread_offset,
        ec_offset: 32,
    };

    let yaml = serde_yaml::to_string(&ruby_2_7_1_offsets).unwrap();

    File::create("src/ruby_versions/ruby_2_7_1.yaml")
        .unwrap()
        .write_all(yaml.as_bytes())
        .unwrap();
}

fn dump_ruby_structs_ruby_2_7_4() {
    let vm_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_4::rb_execution_context_struct,
        vm_stack
    ) as i32;

    let vm_size_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_4::rb_execution_context_struct,
        vm_stack_size
    ) as i32;

    let control_frame_t_sizeof: i32 =
        size_of::<rbspy_ruby_structs::ruby_2_7_4::rb_control_frame_struct>() as i32;

    let cfp_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_4::rb_execution_context_struct,
        cfp
    ) as i32;

    let label_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_4::rb_iseq_location_struct,
        label
    ) as i32;

    let line_info_table_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_4::rb_iseq_constant_body,
        insns_info
    ) as i32;

    let line_info_size_offset: i32 = line_info_table_offset
        + (offset_of!(
            rbspy_ruby_structs::ruby_2_7_4::rb_iseq_constant_body_iseq_insn_info,
            size
        ) as i32);

    let main_thread_offset: i32 =
        offset_of!(rbspy_ruby_structs::ruby_2_7_4::rb_vm_struct, main_thread) as i32;

    let ruby_2_7_4_offsets = RubyVersionOffsets {
        major_version: 2,
        minor_version: 7,
        patch_version: 4,
        vm_offset,
        vm_size_offset,
        control_frame_t_sizeof,
        cfp_offset,
        label_offset,
        path_flavour: 1,
        line_info_size_offset,
        line_info_table_offset,
        lineno_offset: 0,
        main_thread_offset,
        ec_offset: 32,
    };

    let yaml = serde_yaml::to_string(&ruby_2_7_4_offsets).unwrap();

    File::create("src/ruby_versions/ruby_2_7_4.yaml")
        .unwrap()
        .write_all(yaml.as_bytes())
        .unwrap();
}

fn dump_ruby_structs_ruby_2_7_6() {
    let vm_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_6::rb_execution_context_struct,
        vm_stack
    ) as i32;

    let vm_size_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_6::rb_execution_context_struct,
        vm_stack_size
    ) as i32;

    let control_frame_t_sizeof: i32 =
        size_of::<rbspy_ruby_structs::ruby_2_7_6::rb_control_frame_struct>() as i32;

    let cfp_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_6::rb_execution_context_struct,
        cfp
    ) as i32;

    let label_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_6::rb_iseq_location_struct,
        label
    ) as i32;

    let line_info_table_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_2_7_6::rb_iseq_constant_body,
        insns_info
    ) as i32;

    let line_info_size_offset: i32 = line_info_table_offset
        + (offset_of!(
            rbspy_ruby_structs::ruby_2_7_6::rb_iseq_constant_body_iseq_insn_info,
            size
        ) as i32);

    let main_thread_offset: i32 =
        offset_of!(rbspy_ruby_structs::ruby_2_7_6::rb_vm_struct, main_thread) as i32;

    let ruby_2_7_6_offsets = RubyVersionOffsets {
        major_version: 2,
        minor_version: 7,
        patch_version: 6,
        vm_offset,
        vm_size_offset,
        control_frame_t_sizeof,
        cfp_offset,
        label_offset,
        path_flavour: 1,
        line_info_size_offset,
        line_info_table_offset,
        lineno_offset: 0,
        main_thread_offset,
        ec_offset: 32,
    };

    let yaml = serde_yaml::to_string(&ruby_2_7_6_offsets).unwrap();

    File::create("src/ruby_versions/ruby_2_7_6.yaml")
        .unwrap()
        .write_all(yaml.as_bytes())
        .unwrap();
}
fn dump_ruby_structs_ruby_3_0_0() {
    let vm_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_0_0::rb_execution_context_struct,
        vm_stack
    ) as i32;

    let vm_size_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_0_0::rb_execution_context_struct,
        vm_stack_size
    ) as i32;

    let control_frame_t_sizeof: i32 =
        size_of::<rbspy_ruby_structs::ruby_3_0_0::rb_control_frame_struct>() as i32;

    let cfp_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_0_0::rb_execution_context_struct,
        cfp
    ) as i32;

    let label_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_0_0::rb_iseq_location_struct,
        label
    ) as i32;

    let line_info_table_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_0_0::rb_iseq_constant_body,
        insns_info
    ) as i32;

    let line_info_size_offset: i32 = line_info_table_offset
        + (offset_of!(
            rbspy_ruby_structs::ruby_3_0_0::rb_iseq_constant_body_iseq_insn_info,
            size
        ) as i32);

    let main_thread_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_0_0::rb_vm_struct__bindgen_ty_1,
        main_thread
    ) as i32;

    let ruby_3_0_0_offsets = RubyVersionOffsets {
        major_version: 3,
        minor_version: 0,
        patch_version: 0,
        vm_offset,
        vm_size_offset,
        control_frame_t_sizeof,
        cfp_offset,
        label_offset,
        path_flavour: 1,
        line_info_size_offset,
        line_info_table_offset,
        lineno_offset: 0,
        main_thread_offset,
        // we want: ruby_current_vm_ptr->ractor->main_thread->ractor(->threads)->running_ec
        // we have: ruby_current_vm_ptr->ractor->main_thread

        // .ractor
        // (gdb) p/d offsetof(struct rb_thread_struct, ractor)
        // $15 = 24

        // .running_ec
        //                                                                                                          /* hole */                                                                                /* hole */
        // (gdb) p/d sizeof(struct rb_ractor_pub) + sizeof(struct rb_ractor_sync) + sizeof(VALUE) + sizeof(_Bool) + 7 + sizeof(rb_nativethread_cond_t) + sizeof(struct list_head) + sizeof(unsigned int) *3 + 4 + sizeof(rb_global_vm_lock_t)
        // $16 = 520
        ec_offset: 520,
    };

    let yaml = serde_yaml::to_string(&ruby_3_0_0_offsets).unwrap();

    File::create("src/ruby_versions/ruby_3_0_0.yaml")
        .unwrap()
        .write_all(yaml.as_bytes())
        .unwrap();
}

fn dump_ruby_structs_ruby_3_0_4() {
    let vm_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_0_4::rb_execution_context_struct,
        vm_stack
    ) as i32;

    let vm_size_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_0_4::rb_execution_context_struct,
        vm_stack_size
    ) as i32;

    let control_frame_t_sizeof: i32 =
        size_of::<rbspy_ruby_structs::ruby_3_0_4::rb_control_frame_struct>() as i32;

    let cfp_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_0_4::rb_execution_context_struct,
        cfp
    ) as i32;

    let label_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_0_4::rb_iseq_location_struct,
        label
    ) as i32;

    let line_info_table_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_0_4::rb_iseq_constant_body,
        insns_info
    ) as i32;

    let line_info_size_offset: i32 = line_info_table_offset
        + (offset_of!(
            rbspy_ruby_structs::ruby_3_0_4::rb_iseq_constant_body_iseq_insn_info,
            size
        ) as i32);

    let main_thread_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_0_4::rb_vm_struct__bindgen_ty_1,
        main_thread
    ) as i32;

    let ruby_3_0_4_offsets = RubyVersionOffsets {
        major_version: 3,
        minor_version: 0,
        patch_version: 4,
        vm_offset,
        vm_size_offset,
        control_frame_t_sizeof,
        cfp_offset,
        label_offset,
        path_flavour: 1,
        line_info_size_offset,
        line_info_table_offset,
        lineno_offset: 0,
        main_thread_offset,
        // we want: ruby_current_vm_ptr->ractor->main_thread->ractor(->threads)->running_ec
        // we have: ruby_current_vm_ptr->ractor->main_thread

        // .ractor
        // (gdb) p/d offsetof(struct rb_thread_struct, ractor)
        // $15 = 24

        // .running_ec
        //                                                                                                          /* hole */                                                                                /* hole */
        // (gdb) p/d sizeof(struct rb_ractor_pub) + sizeof(struct rb_ractor_sync) + sizeof(VALUE) + sizeof(_Bool) + 7 + sizeof(rb_nativethread_cond_t) + sizeof(struct list_head) + sizeof(unsigned int) *3 + 4 + sizeof(rb_global_vm_lock_t)
        // $16 = 520
        ec_offset: 520,
    };

    let yaml = serde_yaml::to_string(&ruby_3_0_4_offsets).unwrap();

    File::create("src/ruby_versions/ruby_3_0_4.yaml")
        .unwrap()
        .write_all(yaml.as_bytes())
        .unwrap();
}

fn dump_ruby_structs_ruby_3_1_2() {
    let vm_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_1_2::rb_execution_context_struct,
        vm_stack
    ) as i32;

    let vm_size_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_1_2::rb_execution_context_struct,
        vm_stack_size
    ) as i32;

    let control_frame_t_sizeof: i32 =
        size_of::<rbspy_ruby_structs::ruby_3_1_2::rb_control_frame_struct>() as i32;

    let cfp_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_1_2::rb_execution_context_struct,
        cfp
    ) as i32;

    let label_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_1_2::rb_iseq_location_struct,
        label
    ) as i32;

    let line_info_table_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_1_2::rb_iseq_constant_body,
        insns_info
    ) as i32;

    let line_info_size_offset: i32 = line_info_table_offset
        + (offset_of!(
            rbspy_ruby_structs::ruby_3_1_2::rb_iseq_constant_body_iseq_insn_info,
            size
        ) as i32);

    let main_thread_offset: i32 = offset_of!(
        rbspy_ruby_structs::ruby_3_1_2::rb_vm_struct__bindgen_ty_1,
        main_thread
    ) as i32;

    let ruby_3_1_2_offsets = RubyVersionOffsets {
        major_version: 3,
        minor_version: 1,
        patch_version: 2,
        vm_offset,
        vm_size_offset,
        control_frame_t_sizeof,
        cfp_offset,
        label_offset,
        path_flavour: 1,
        line_info_size_offset,
        line_info_table_offset,
        lineno_offset: 0,
        main_thread_offset,
        // we want: ruby_current_vm_ptr->ractor->main_thread->ractor(->threads)->running_ec
        // we have: ruby_current_vm_ptr->ractor->main_thread

        // .ractor
        // (gdb) p/d offsetof(struct rb_thread_struct, ractor)
        // $15 = 24

        // .running_ec
        //                                                                                                          /* hole */                                                                                /* hole */
        // (gdb) p/d sizeof(struct rb_ractor_pub) + sizeof(struct rb_ractor_sync) + sizeof(VALUE) + sizeof(_Bool) + 7 + sizeof(rb_nativethread_cond_t) + sizeof(struct list_head) + sizeof(unsigned int) *3 + 4 + sizeof(rb_global_vm_lock_t)
        // $16 = 520
        ec_offset: 520,
    };

    let yaml = serde_yaml::to_string(&ruby_3_1_2_offsets).unwrap();

    File::create("src/ruby_versions/ruby_3_1_2.yaml")
        .unwrap()
        .write_all(yaml.as_bytes())
        .unwrap();
}

fn main() {
    dump_ruby_structs_ruby_2_6_0();
    dump_ruby_structs_ruby_2_6_3();

    dump_ruby_structs_ruby_2_7_1();
    dump_ruby_structs_ruby_2_7_4();
    dump_ruby_structs_ruby_2_7_6();

    dump_ruby_structs_ruby_3_0_0();
    dump_ruby_structs_ruby_3_0_4();
    dump_ruby_structs_ruby_3_1_2();
}
