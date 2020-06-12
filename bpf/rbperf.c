// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#include <linux/sched.h>
#include <uapi/linux/bpf_perf_event.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>

#define MAX_STACKS_PER_PROGRAM __MAX_STACKS_PER_PROGRAM__
#define BPF_PROGRAMS_COUNT __BPF_PROGRAMS_COUNT__
#define MAX_STACK (MAX_STACKS_PER_PROGRAM * BPF_PROGRAMS_COUNT)
#define COMM_MAXLEN 25
#define METHOD_MAXLEN 50
#define PATH_MAXLEN 150

#include "bpf/rbperf.h"

BPF_PERF_OUTPUT(events);
BPF_HASH(pid_to_rb_thread, u32, ProcessData);
BPF_HASH(id_to_stack, u32, RubyFrame);
BPF_HASH(stack_to_id, RubyFrame, u32);
BPF_ARRAY(version_specific_offsets, RubyVersionOffsets, 10);
BPF_PERCPU_ARRAY(scratch_stack, RubyStackAddresses, 1);
BPF_PERCPU_ARRAY(global_state, SampleState, 1);
BPF_PROG_ARRAY(programs, 1);

static inline_method u32 find_or_insert_frame(RubyFrame *frame) {
    u32 *found_id = stack_to_id.lookup(frame);
    if (found_id != NULL) {
        return *found_id;
    }
    // TODO(javierhonduco): Instead of calling the random number generator
    // we could generate unique IDs per CPU.
    u32 random = bpf_get_prandom_u32();
    // TODO(javierhonduco): Use smaller value as we won't read it
    stack_to_id.insert(frame, &random);
    id_to_stack.insert(&random, frame);
    return random;
}

static inline_method void read_ruby_string(u64 label, char *buffer,
                                           int buffer_len) {
    u64 flags;
    u64 char_ptr;

    rbperf_read(&flags, 8, (void *)(label + 0 + 0));

    if (STRING_ON_HEAP(flags)) {
        rbperf_read(&char_ptr, 8,
                    (void *)(label + as_offset + 8 /* sizeof(long) */));
        rbperf_read_str(buffer, buffer_len, (void *)(char_ptr));
    } else {
        rbperf_read_str(buffer, buffer_len, (void *)(label + as_offset));
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
        // Skip as we don't have the data types we were looking for
        return;
    }

    rbperf_read(&label, 8,
                (void *)(body + location_offset + label_offset));

    read_ruby_string(path, current_frame->path, sizeof(current_frame->path));
    current_frame->lineno = read_ruby_lineno(pc, body, version_offsets);
    read_ruby_string(label, current_frame->method_name,
                     sizeof(current_frame->method_name));
}

int read_ruby_frames(struct bpf_perf_event_data *ctx) {
    u64 iseq_addr;
    u64 pc;
    u64 body;

    int zero = 0;
    SampleState *state = global_state.lookup(&zero);
    if (state == NULL) {
        return 0;  // this should never happen
    }
    RubyVersionOffsets *version_offsets =
        version_specific_offsets.lookup(&state->rb_version);
    if (version_offsets == NULL) {
        return 0;  // this should not happen
    }

    RubyFrame current_frame = {};
    u64 base_stack = state->base_stack;
    u64 cfp = state->cfp;
    state->ruby_stack_program_count += 1;
    u64 control_frame_t_sizeof = version_offsets->control_frame_t_sizeof;

    RubyStackAddresses *ruby_stack_addresses =
        scratch_stack.lookup(&zero);
    if (ruby_stack_addresses == NULL) {
        return 0;  // this should never happen
    }

    // TODO(javierhonduco): Do not go past max stack
    int rb_frame_count = 0;
#pragma unroll
    for (int i = 0; i < MAX_STACKS_PER_PROGRAM; i++) {
        // TODO(javierhonduco): we know the actual stack size, we may exit the loop earlier
        rbperf_read(&iseq_addr, 8, (void *)(base_stack + iseq_offset));
        rbperf_read(&pc, 8, (void *)(base_stack + 0));

        if ((void *)iseq_addr == NULL) {
            goto skip;
        }
        if ((void *)pc == NULL) {
            // this could be a C frame:
            // https://github.com/ruby/ruby/blob/4ff3f20/.gdbinit#L1056
            goto skip;
        }

        RubyStackAddress ruby_stack_address = {.iseq_addr = iseq_addr,
                                               .pc = pc};
        unsigned long long offset = rb_frame_count + state->rb_frame_count;
        if (offset >= 0 && offset < MAX_STACK) {
            ruby_stack_addresses->ruby_stack_address[offset] = ruby_stack_address;
        }
        rb_frame_count += 1;

    skip:
        base_stack -= control_frame_t_sizeof;
    }

    RubyStack *current_stack = &state->stack;

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

        rbperf_read(&body, 8, (void *)(iseq_addr + body_offset));
        read_frame(pc, body, &current_frame, version_offsets);

        long long int actual_index = current_stack->size;
        if (actual_index >= 0 && actual_index < MAX_STACK) {
            current_stack->frames[actual_index] = find_or_insert_frame(&current_frame);
            current_stack->size += 1;
        }
    }
end:
    state->rb_frame_count += rb_frame_count;
    state->base_stack = base_stack;

    current_stack->stack_status =
        cfp >= base_stack ? STACK_COMPLETE : STACK_INCOMPLETE;
    if (cfp < base_stack &&
        state->ruby_stack_program_count < BPF_PROGRAMS_COUNT) {
        programs.call(ctx, 0);
    }

    events.perf_submit(ctx, current_stack, sizeof(RubyStack));
    return 0;
}

int on_event(struct bpf_perf_event_data *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    ProcessData *process_data = pid_to_rb_thread.lookup(&pid);

    if (process_data != NULL && process_data->rb_frame_addr != 0) {
        u64 ruby_current_thread_addr;
        u64 thread_stack_content;
        u64 thread_stack_size;
        u64 cfp;
        int control_frame_t_sizeof;

        RubyVersionOffsets *version_offsets =
            version_specific_offsets.lookup(&process_data->rb_version);
        if (version_offsets == NULL) {
            return 0;  // this should not happen
        }

        rbperf_read(&ruby_current_thread_addr, 8,
                    (void *)process_data->rb_frame_addr);
        control_frame_t_sizeof = version_offsets->control_frame_t_sizeof;

        rbperf_read(
            &thread_stack_content, 8,
            (void *)(ruby_current_thread_addr + version_offsets->vm_offset));
        rbperf_read(
            &thread_stack_size, 8,
            (void *)(ruby_current_thread_addr + version_offsets->vm_size_offset));

        // TODO(javierhonduco): check what `(rb_control_frame_t *) - 1` is
        u64 base_stack = thread_stack_content +
                         rb_value_sizeof * thread_stack_size -
                         2 * control_frame_t_sizeof;
        rbperf_read(&cfp, 8, (void *)(ruby_current_thread_addr + version_offsets->cfp_offset));
        int zero = 0;
        SampleState *state = global_state.lookup(&zero);
        if (state == NULL) {
            return 0;  // this should never happen
        }

        // Set the global state, shared across bpf tail calls
        state->stack.timestamp = bpf_ktime_get_ns();
        state->stack.pid = pid;
        state->stack.cpu = bpf_get_smp_processor_id();
        state->stack.size = 0;
        bpf_get_current_comm(state->stack.comm, sizeof(state->stack.comm));
        state->stack.stack_status = STACK_COMPLETE;

        state->base_stack = base_stack;
        state->cfp = cfp;
        state->ruby_stack_program_count = 0;
        state->rb_frame_count = 0;
        state->rb_version = process_data->rb_version;

        programs.call(ctx, 0);
        // This will never be executed
        return 0;
    }
    return 0;
}
