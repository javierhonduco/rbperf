rbperf
======

`rbperf` is a low-overhead sampling profiler and tracer for Ruby (CRuby) which runs in BPF

## Build

To build `rbperf` you would need a Linux machine with:
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

Stay tuned for pre-compiled binaries! 

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

## Stability

`rbperf` is in active development and the CLI and APIs might change any time

## Bugs

If you encounter any bugs, feel free to open an issue on rbperf's [repo](https://github.com/javierhonduco/rbperf)

## Acknowledgements

`rbperf` wouldn't be possible without all the open source projects that we benefit from, such as Rust and all the superb crates we use in this project, Ruby and its [GDB file](https://github.com/ruby/ruby/blob/master/.gdbinit), the BPF ecosystem, and many others!

## License

Licensed under the MIT license
