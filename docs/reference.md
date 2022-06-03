## Compilation

To compile rbperf you will need:
- the Rust compiler toolchain (https://rustup.rs/)
- a modern version of the `clang` compiler
- `elfutils` and `zlib` (needed by libbpf)

These dependencies can be installed with `sudo dnf install clang elfutils zlib` on Fedora.

Once the needed toolchain and dependencies are installed:
```
$ cargo build 
```

## Usage

rbperf is a sampling CPU profiler as well as a system call tracer. In CPU profiling mode, it will periodically fetch the Ruby stacktrace of the traced process. As a system call tracer, it will read a stacktrace everytime that the provided system call is executed.

### CPU sampling

```
$ sudo ./target/debug/rbperf record --pid `pidof ruby` cpu
```

### System call tracing

The available system calls to trace can be found with `sudo ls /sys/kernel/debug/tracing/events/syscalls/`

```
$ sudo ./target/debug/rbperf record --pid `pidof ruby` syscall enter_writev
```