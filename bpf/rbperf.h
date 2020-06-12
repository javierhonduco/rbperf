// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#if READ_USERSPACE_ADDRESS_SPACE
#define rbperf_read bpf_probe_read_user
#define rbperf_read_str bpf_probe_read_user_str
#else
#define rbperf_read bpf_probe_read
#define rbperf_read_str bpf_probe_read_str
#endif

#ifdef USE_ABSOLUTE_PATH
// TODO(javierhonduco): Add test for this
#define PATH_TYPE_OFFSET 0x8  // ABSOLUTE_PATH_OFFSET
#else
#define PATH_TYPE_OFFSET 0x0  // RELATIVE_PATH_OFFSET
#endif

#define rb_value_sizeof 0x8  // sizeof(VALUE)

#define iseq_offset 0x10      // offsetof(rb_control_frame_t, iseq)
#define body_offset 0x10      // offsetof(struct rb_iseq_struct, body)
#define location_offset 0x40  // offsetof(struct rb_iseq_constant_body, location)
#define path_offset 0x0       // offsetof(struct rb_iseq_location_struct, path)
#define iseq_encoded_offset \
    0x8  // offsetof(struct rb_iseq_constant_body, iseq_encoded)

#define as_offset 0x10

#define STRING_ON_HEAP(flags) flags &(1 << 13)
#define inline_method inline __attribute__((__always_inline__))

// CRuby constants, from
// https://github.com/ruby/ruby/blob/4ff3f20/include/ruby/3/value_type.h
#define RUBY_T_MASK 0x1f
#define RUBY_T_STRING 0x05
#define RUBY_T_ARRAY 0x07

enum ruby_stack_status {
    STACK_COMPLETE = 0,
    STACK_INCOMPLETE = 1,
};

typedef struct {
    u32 lineno;
    char method_name[METHOD_MAXLEN];
    char path[PATH_MAXLEN];
} RubyFrame;

typedef struct {
    u64 timestamp;
    u32 frames[MAX_STACK];
    u32 pid;
    u32 cpu;
    long long int size;
    char comm[COMM_MAXLEN];
    enum ruby_stack_status stack_status;
} RubyStack;

typedef struct {
    RubyStack stack;
    u64 base_stack;
    u64 cfp;
    int ruby_stack_program_count;
    long long int rb_frame_count;
    int rb_version;
} SampleState;

typedef struct {
    u64 rb_frame_addr;
    int rb_version;
} ProcessData;

typedef struct {
    int vm_offset;
    int vm_size_offset;
    int control_frame_t_sizeof;
    int cfp_offset;
    int label_offset;
    int path_flavour;
    int line_info_size_offset;
    int line_info_table_offset;
    int lineno_offset;
} RubyVersionOffsets;

typedef struct {
    u64 iseq_addr;
    u64 pc;
} RubyStackAddress;

typedef struct {
    RubyStackAddress ruby_stack_address[MAX_STACK];
} RubyStackAddresses;
