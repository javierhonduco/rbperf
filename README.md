# rbperf

rbperf is an experimental Ruby Profiler that runs in Linux's eBPF VM (extended Berkeley Packet Filters)

## Installation
You'll need [libbcc installed](https://github.com/iovisor/bcc/blob/master/INSTALL.md) in your system, a recent Linux kernel, and Python 3.6+.

```shell
$ python3 setup.py install
```

## Usage
CPU profiling, takes a sample every 1 million CPU cycles across all CPUs:

```shell
$ sudo bin/rbperf record --pid=12774 cpu
Sampling every 1,000,000 CPU cycles
Profiling pid: 12774 (Ruby 2.6.4) with addr: 0x7f6bd136a920
^CReceived sigint, exiting...
Processed 832 events, lost 0 events, lost stacks 0, incomplete: 90, written: 832
Profile written to rbperf-2020-05-10T18:43:08.data
```

This writes a serialised profile to disk. Let's convert it into something more useful, like a flamegraph:
```shell
$ sudo rbperf report --input rbperf-2020-05-10T18:43:08.data --output /tmp/rbperf_flamegraph.html --format=flamegraph
```

And open the flamegraph in your favourite browser!

To learn more, check out the [Tutorial](https://github.com/facebookexperimental/rbperf/blob/master/docs/tutorial.md) and the [Investigation Example](https://github.com/facebookexperimental/rbperf/blob/master/docs/investigation_example.md)

## Features / Limitations

### Features
- Low overhead: can be run in production and it's suitable for continuous profiling
- Does not require modifications in the profiled code
- Can be used as a CLI and as a library. Bear in mind the APIs are not stable yet
- Uses Protocol Buffers to serialise profiles to disk, so pretty much any language that process them
- The CPU profiling mode - the one by default - actually records on-CPU profiles
- USDTs and tracepoints tracing, see `rbperf --pid=$PID event --help`

### Limitations
- Line numbers are not accurate and and probably won't ever be. This is due to how they are encoded in the Ruby VM and the way BPF works
- If the stacks are **very** big, it is possible that we won't be able to fetch it in its entirety (check `--bpf-progs`. Using a kernel newer than 5.3 also helps here due to the increase in maximum BPF instructions!)
- Requires recent kernels
- It probably won't work inside of containers, as the container's PID namespaces as the initial PID namespace will differ (this might change in the future thanks to a recent patch)

## Design
There are two main parts: the BPF program, in `bpf/`, and the "driver" program, `rbperf.py`. The first one runs in Kernel space and it's invoked by different events, such as each _n_ CPU cycles, or whenever a particular Kernel tracepoint is called. The driver runs in userspace and its responsible for filling in some data structures that the BPF program needs, as well as processing the events it receives from it.

Right now, said driver is written in Python, leveraging [BCC](https://github.com/iovisor/bcc/), as we'd like to optimise for development speed and flexibility. We might change this in the future, but our current focus is on the correctness of the stack walking. We want to make sure the stacktraces are accurate and that the errors we provide make sense first.

If you have any thoughts or questions, feel free to open an issue.

*Note*: A more throughout document on how `rbperf` works will be eventually published.

## Hacking

You'd need a modern Linux (5.3 or greater if possible) and git LFS.

Install it in dev mode:

```shell
$ python3 setup.py develop
```

run the tests and typechecker:

```shell
$ sudo bin/test
$ bin/typecheck
````

compile protobufs (you'd need the protocol buffers compiler installed):

```shell
$ bin/proto
```

## License
rbperf is MIT licensed, as found in the LICENSE file.
