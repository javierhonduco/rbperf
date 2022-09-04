#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

bool feature_has_run = false;

bool feature_is_jited = false;
bool feature_has_stats = false;
bool feature_has_tail_call = false;
bool feature_has_ringbuf = false;
bool feature_bpf_loop = false;

SEC("kprobe/hrtimer_start_range_ns")
int features_entry() {
    static struct bpf_prog *bpf_prog = NULL;
    feature_has_run = true;

    feature_is_jited = bpf_core_field_exists(bpf_prog->jited);
    feature_has_stats = bpf_core_field_exists(bpf_prog->stats);
    feature_has_ringbuf = bpf_core_enum_value_exists(enum bpf_map_type, BPF_MAP_TYPE_RINGBUF);
    feature_has_tail_call = bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_tail_call);
    feature_has_ringbuf = bpf_core_enum_value_exists(enum bpf_map_type, BPF_MAP_TYPE_RINGBUF);
    feature_bpf_loop = bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_loop);

    return 0;
}