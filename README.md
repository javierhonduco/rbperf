rbperf
======

`rbperf` is a low-overhead sampling profiler and tracer for Ruby (CRuby) which runs in BPF

## Build

To build `rbperf` you would need a Linux machine with:
- The Rust toolchain
- `clang` to compile the BPF code
- `elfutils` and `zlib` installed

Once the dependencies are installed:
```shell
$ cargo build [--release]
```

Pre-compiled binaries are planned in the near future

## Usage

### CPU sampling

```
$ sudo rbperf record --pid `pidof ruby` cpu
```

### System call tracing

The available system calls to trace can be found with `sudo ls /sys/kernel/debug/tracing/events/syscalls/`

```
$ sudo rbperf record --pid `pidof ruby` syscall enter_writev
```

## Stability

`rbperf` is in active development and the CLI and APIs might change any time

## License

Licensed under the MIT license
