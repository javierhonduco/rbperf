# rbperf tutorial

This tutorial covers some of the things you can achieve with rbperf:

## Recording

This will save the profile to disk and show some statistics

### CPU profiling
```
$ sudo bin/rbperf record --pid=$PID cpu [--period=1000000]
```

This will sample all the CPUs in your machine every `--period` CPU cycles. By default every million cycles. Note that if Ruby is not running on the CPU when the samples are taken, we won't get any samples.

### USDT tracing
```
$ sudo bin/rbperf record --pid=$PID event --usdt=raise
```

Ruby (MRI) has [USDT Probes](https://github.com/ruby/ruby/blob/afd84c5/doc/dtrace_probes.rdoc) we can attach to, like `raise`, which will fire an event every time an exception is raised. Note that the syntax to use here is slightly different, you'd need double underscores instead of dashes, so `load-entry` will become `load__entry`

### Kernel tracepoints

The Linux Kernel exposes some events we can attach to called tracepoints invoked in different Kernel subsystem's events. If you have `perf` installed, you can check the ones in your system with `perf list |& grep Tracepoint`, alternatively, with `bpftrace` you can do `sudo bpftrace -l | grep tracepoint:`

This allows us, for example, to see all the Ruby stacks that call [`write(2)`](http://man7.org/linux/man-pages/man2/write.2.html):

```
$ sudo bin/rbperf record --pid=$PID event --tracepoint=syscalls:sys_enter_write
````

**Stats**:
When you finish profiling, you'll see something like:

```
Processed 132 events, lost 0 events, lost stacks 0, incomplete: 0, written: 132
```

Let's break this down:
- We processed 132 events, that is, stacktraces that BPF program which walks stacks sent us in a perf buffer
- 0 stacks got lost in the perf buffer
- 0 stacks got lost due to issues accesing the frames
- There are no incomplete frames, we were able to capture the whole stack. The BPF VM allows for a max number of instructions, in modern Kernels 1 million. This might not be enough if your stacks are very very deep. We also use tail BPF calls, you can increase this number passing `--bpf-progs`, up to 30 in current kernels
- Finally, we have written 132 stacks to disk!


## Reporting

Once this information is stored on disk, we can analyse it with `rbperf report`:

```
$ sudo bin/rbperf report --input rbperf-[...].data --output /tmp/omg --format=(flamegraph|folded|stdout)
```

Right now we have 3 output formats:
- `flamegraph`: [a visualisation](http://www.brendangregg.com/flamegraphs.html) that makes it way easier to understand hotspots in your code. We are inverting the flamegraph's order, which is called icicle, but calling them Flamegraphs to use the most used name :)
- `folded`: in each line we have a stack and the number of times it appears. The stack has each frame separated by a semicolon. This is the format many performance visualisation tools use
- `stdout`: just print the stack's contents to standard output, useful when debugging rbperf
