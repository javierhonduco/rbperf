// Copyright (c) Facebook, Inc. and its affiliates.
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
//
// Copyright (c) 2022 The rbperf authors

#include "rbperf.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3);
    __type(key, u32);
    __type(value, u32);
} programs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, ProcessData);
} pid_to_rb_thread SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, RubyFrame);
} id_to_stack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, RubyFrame);
    __type(value, u32);
} stack_to_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, RubyVersionOffsets);
} version_specific_offsets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, RubyStackAddresses);
} scratch_stack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, SampleState);
} global_state SEC(".maps");

static inline_method u32 find_or_insert_frame(RubyFrame *frame) {
    u32 *found_id = bpf_map_lookup_elem(&stack_to_id, frame);
    if (found_id != NULL) {
        return *found_id;
    }
    // TODO(javierhonduco): Instead of calling the random number generator
    // we could generate unique IDs per CPU.
    u32 random = bpf_get_prandom_u32();
    bpf_map_update_elem(&stack_to_id, frame, &random, BPF_ANY);
    bpf_map_update_elem(&id_to_stack, &random, frame, BPF_ANY);
    return random;
}

static inline_method void read_ruby_string(u64 label, char *buffer,
                                           int buffer_len) {
    u64 flags;
    u64 char_ptr;

    rbperf_read(&flags, 8, (void *)(label + 0 /* .basic */ + 0 /* .flags */));

    if (STRING_ON_HEAP(flags)) {
        rbperf_read(&char_ptr, 8,
                    (void *)(label + as_offset + 8 /* .long len */));
        int err = rbperf_read_str(buffer, buffer_len, (void *)(char_ptr));
        if (err < 0) {
            bpf_printk("[warn] string @ 0x%llx [heap] failed with err=%d", (void *)(char_ptr), err);
        }
    } else {
        int err = rbperf_read_str(buffer, buffer_len, (void *)(label + as_offset));
        if (err < 0) {
            bpf_printk("[warn] string @ 0x%llx [stack] failed with err=%d", (void *)(label + as_offset), err);
        }
    }
}

static inline_method int
read_ruby_lineno(u64 pc, u64 body, RubyVersionOffsets *version_offsets) {
    // This will only give accurate line number for Ruby 2.4

    u64 pos_addr;
    u64 pos;
    u64 info_table;
    u32 line_info_size;
    u32 lineno;

    // Native functions have 0 as pc
    if (pc == 0) {
        return 0;
    }

    rbperf_read(&pos_addr, 8, (void *)(pc - body + iseq_encoded_offset));
    rbperf_read(&pos, 8, (void *)pos_addr);

    if (pos != 0) {
        pos -= rb_value_sizeof;
    }

    rbperf_read(&line_info_size, 4,
                (void *)(body + version_offsets->line_info_size_offset));
    if (line_info_size == 0) {
        return line_info_size;
    } else {
        rbperf_read(
            &info_table, 8,
            (void *)(body + version_offsets->line_info_table_offset));
        rbperf_read(&lineno, 4,
                    (void *)(info_table + (line_info_size - 1) * 0x8 +
                             version_offsets->lineno_offset));
        return lineno;
    }
}

static inline_method void
read_frame(u64 pc, u64 body, RubyFrame *current_frame,
           RubyVersionOffsets *version_offsets) {
    u64 path_addr;
    u64 path;
    u64 label;
    u64 flags;
    int label_offset = version_offsets->label_offset;

    bpf_printk("[debug] reading stack");

    rbperf_read(&path_addr, 8,
                (void *)(body + location_offset + path_offset));
    rbperf_read(&flags, 8, (void *)path_addr);
    if ((flags & RUBY_T_MASK) == RUBY_T_STRING) {
        path = path_addr;
    } else if ((flags & RUBY_T_MASK) == RUBY_T_ARRAY) {
        if (version_offsets->path_flavour == 1) {
            // sizeof(struct RBasic)
            path_addr = path_addr + 0x10 /* offset(..., as) */ + PATH_TYPE_OFFSET;
            rbperf_read(&path, 8, (void *)path_addr);
        } else {
            path = path_addr;
        }

    } else {
        bpf_printk("[error] read_frame, wrong type");
        // Skip as we don't have the data types we were looking for
        return;
    }

    rbperf_read(&label, 8,
                (void *)(body + location_offset + label_offset));

    read_ruby_string(path, current_frame->path, sizeof(current_frame->path));
    current_frame->lineno = read_ruby_lineno(pc, body, version_offsets);
    read_ruby_string(label, current_frame->method_name,
                     sizeof(current_frame->method_name));

    bpf_printk("[debug] method name=%s", current_frame->method_name);
}

SEC("perf_event")
int read_ruby_stack(struct bpf_perf_event_data *ctx) {
    u64 iseq_addr;
    u64 pc;
    u64 pc_addr;
    u64 body;

    int zero = 0;
    SampleState *state = bpf_map_lookup_elem(&global_state, &zero);
    if (state == NULL) {
        return 0;  // this should never happen
    }
    RubyVersionOffsets *version_offsets = bpf_map_lookup_elem(&version_specific_offsets, &state->rb_version);
    if (version_offsets == NULL) {
        return 0;  // this should not happen
    }

    RubyFrame current_frame = {};
    u64 base_stack = state->base_stack;
    u64 cfp = state->cfp;
    state->ruby_stack_program_count += 1;
    u64 control_frame_t_sizeof = version_offsets->control_frame_t_sizeof;

    RubyStackAddresses *ruby_stack_addresses = bpf_map_lookup_elem(&scratch_stack, &zero);
    if (ruby_stack_addresses == NULL) {
        return 0;  // this should never happen
    }

    int rb_frame_count = 0;

#pragma unroll
    for (int i = 0; i < MAX_STACKS_PER_PROGRAM; i++) {
        rbperf_read(&iseq_addr, 8, (void *)(cfp + iseq_offset));
        rbperf_read(&pc_addr, 8, (void *)(cfp + 0));
        rbperf_read(&pc, 8, (void *)pc_addr);

        RubyStackAddress ruby_stack_address = {};

        if (cfp > state->base_stack) {
            bpf_printk("[debug] done reading stack");
            break;
        }

        if ((void *)iseq_addr == NULL) {
            // this could be a native frame, it's missing the check though
            // https://github.com/ruby/ruby/blob/4ff3f20/.gdbinit#L1155
            ruby_stack_address.iseq_addr = NATIVE_METHOD_MARKER;
            ruby_stack_address.pc = NATIVE_METHOD_MARKER;
        } else {
            ruby_stack_address.iseq_addr = iseq_addr;
            ruby_stack_address.pc = pc;
        }

        unsigned long long offset = rb_frame_count + state->rb_frame_count;
        if (offset >= 0 && offset < MAX_STACK) {
            ruby_stack_addresses->ruby_stack_address[offset] = ruby_stack_address;
        }
        rb_frame_count += 1;

    skip:
        cfp += control_frame_t_sizeof;
    }

    state->cfp = cfp;

#pragma unroll
    for (int i = 0; i < MAX_STACKS_PER_PROGRAM; i++) {
        RubyStackAddress ruby_stack_address;
        unsigned long long offset = i + state->rb_frame_count;
        if (i >= rb_frame_count) {
            goto end;
        }
        if (offset >= 0 && offset < MAX_STACK) {
            ruby_stack_address = ruby_stack_addresses->ruby_stack_address[offset];
        } else {
            // this should never happen
            return 0;
        }
        iseq_addr = ruby_stack_address.iseq_addr;
        pc = ruby_stack_address.pc;

        if (iseq_addr == NATIVE_METHOD_MARKER && pc == NATIVE_METHOD_MARKER) {
            bpf_probe_read_kernel_str(current_frame.method_name, sizeof(NATIVE_METHOD_NAME), NATIVE_METHOD_NAME);
        } else {
            rbperf_read(&body, 8, (void *)(iseq_addr + body_offset));
            // add check
            read_frame(pc, body, &current_frame, version_offsets);
        }

        long long int actual_index = state->stack.size;
        if (actual_index >= 0 && actual_index < MAX_STACK) {
            state->stack.frames[actual_index] = find_or_insert_frame(&current_frame);
            state->stack.size += 1;
        }
    }
end:
    state->rb_frame_count += rb_frame_count;
    state->base_stack = base_stack;

    if (cfp <= base_stack &&
        state->ruby_stack_program_count < BPF_PROGRAMS_COUNT) {
        bpf_printk("[debug] traversing next chunk of the stack in a tail call");
        bpf_tail_call(ctx, &programs, RBPERF_STACK_READING_PROGRAM_IDX);
    }

    state->stack.stack_status = cfp > state->base_stack ? STACK_COMPLETE : STACK_INCOMPLETE;

    if (state->stack.size != state->stack.expected_size) {
        bpf_printk("[error] stack size %d, expected %d", state->stack.size, state->stack.expected_size);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &state->stack, sizeof(RubyStack));
    return 0;
}

SEC("perf_event")
int on_event(struct bpf_perf_event_data *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    ProcessData *process_data = bpf_map_lookup_elem(&pid_to_rb_thread, &pid);

    if (process_data != NULL && process_data->rb_frame_addr != 0) {
        bpf_printk("[debug] reading Ruby stack");

        u64 ruby_current_thread_addr;
        u64 main_thread_addr;
        u64 ec_addr;
        u64 thread_stack_content;
        u64 thread_stack_size;
        u64 cfp;
        int control_frame_t_sizeof;
        RubyVersionOffsets *version_offsets = bpf_map_lookup_elem(&version_specific_offsets, &process_data->rb_version);

        if (version_offsets == NULL) {
            bpf_printk("[error] can't find offsets for version");
            return 0;
        }

        rbperf_read(&ruby_current_thread_addr, 8,
                    (void *)process_data->rb_frame_addr);

        bpf_printk("process_data->rb_frame_addr %llx", process_data->rb_frame_addr);
        bpf_printk("ruby_current_thread_addr %llx", ruby_current_thread_addr);

        // Find the main thread and the ec
        rbperf_read(&main_thread_addr, 8,
                    (void *)ruby_current_thread_addr + version_offsets->main_thread_offset);
        rbperf_read(&ec_addr, 8, main_thread_addr + version_offsets->ec_offset);

        control_frame_t_sizeof = version_offsets->control_frame_t_sizeof;

        rbperf_read(
            &thread_stack_content, 8,
            (void *)(ec_addr + version_offsets->vm_offset));
        rbperf_read(
            &thread_stack_size, 8,
            (void *)(ec_addr + version_offsets->vm_size_offset));

        u64 base_stack = thread_stack_content +
                         rb_value_sizeof * thread_stack_size -
                         2 * control_frame_t_sizeof /* skip dummy frames */;
        rbperf_read(&cfp, 8, (void *)(ec_addr + version_offsets->cfp_offset));
        int zero = 0;
        SampleState *state = bpf_map_lookup_elem(&global_state, &zero);
        if (state == NULL) {
            return 0;  // this should never happen
        }

        // Set the global state, shared across bpf tail calls
        state->stack.timestamp = bpf_ktime_get_ns();
        state->stack.pid = pid;
        state->stack.cpu = bpf_get_smp_processor_id();
        state->stack.size = 0;
        state->stack.expected_size = (base_stack - cfp) / control_frame_t_sizeof;
        bpf_get_current_comm(state->stack.comm, sizeof(state->stack.comm));
        state->stack.stack_status = STACK_COMPLETE;

        state->base_stack = base_stack;
        state->cfp = cfp + version_offsets->control_frame_t_sizeof;
        state->ruby_stack_program_count = 0;
        state->rb_frame_count = 0;
        state->rb_version = process_data->rb_version;

        bpf_tail_call(ctx, &programs, RBPERF_STACK_READING_PROGRAM_IDX);
        // This will never be executed
        return 0;
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
