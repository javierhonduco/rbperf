rbperf
======

`rbperf` is a low-overhead sampling profiler and tracer for Ruby (CRuby) which runs in BPF

## Features

The main goals for rbperf are

- On-CPU profiling support
- Low overhead
- Profiled processes don't have to be restarted or modified in any way
- Support for tracing low level events, such as system calls


## Installation

The latest release of is available [here](https://github.com/javierhonduco/rbperf/releases/latest).


## Usage

### CPU sampling

```
$ sudo rbperf record --pid `pidof ruby` cpu
```

### System call tracing

The available system calls to trace can be found with:

```
$ sudo rbperf record --pid `pidof ruby` syscall --list
```

```
$ sudo rbperf record --pid `pidof ruby` syscall enter_writev
```

Some debug information will be printed, and a flamegraph called `rbperf_flame_$date` will be written to disk 🎉

## Supported Ruby versions

The currently supported Ruby versions:
- **2.6**: 2.6.0, 2.6.3
- **2.7**: 2.7.1, 2.7.4, 2.7.6
- **3.x**: 3.0.0, 3.0.4, 3.1.2, 3.1.3, 3.2.0, 3.2.1

## Supported kernels

Linux kernel 4.18 is the minimum required version but 5.x and greater is recommended.

## Building

To build `rbperf` you would need a modern Linux machine with:
- The Rust toolchain
- `clang` to compile the BPF code
- `elfutils` and `zlib` installed
- `make` and `pkg-config` to build libbpf

Once the dependencies are installed:
```shell
# As we are statically linking elfutils and zlib, we have to tell Rustc
# where are they located. On my Ubuntu system they are under
$ export RUSTFLAGS='-L /usr/lib/x86_64-linux-gnu'
$ cargo build [--release]
```

The built binary can be found under `target/(debug|release)/rbperf`.

## Developing and troubleshooting

Debug logs can be enabled with `RUST_LOG=debug`. The info subcommand, `rbperf info` shows the supported BPF features as well as other supported details.


## Stability

`rbperf` is in active development and the CLI and APIs might change any time

## Bugs

If you encounter any bugs, feel free to open an issue on rbperf's [repo](https://github.com/javierhonduco/rbperf)

## Acknowledgements

`rbperf` wouldn't be possible without all the open source projects that we benefit from, such as Rust and all the superb crates we use in this project, Ruby and its [GDB file](https://github.com/ruby/ruby/blob/master/.gdbinit), the BPF ecosystem, and many others!

## License

Licensed under the MIT license
