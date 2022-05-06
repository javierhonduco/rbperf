use bcc::BPFBuilder;

fn main() {
    let code = include_str!("../bpf/rbperf.c");
    let cflags = &[
        "-D__MAX_STACKS_PER_PROGRAM__=25",
        "-D__BPF_PROGRAMS_COUNT__=3",
    ];
    let bpf = BPFBuilder::new(code)
        .unwrap()
        .cflags(cflags)
        .unwrap()
        .build()
        .unwrap();
    println!("bpf: {:?}", bpf);
}
