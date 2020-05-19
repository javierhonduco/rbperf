# Contributing to rbperf

## Requirements
You'd need a modern Linux (5.3 or greater if possible), git LFS, and [libbcc installed](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

## Development

### Installation
After cloning the repository

```shell
git clone https://github.com/facebookexperimental/rbperf && cd rbperf
```

Install rbperf in dev mode with:

```shell
$ python3 setup.py develop
```

### Testing
You can run the test suite with::

```shell
$ sudo bin/test
````

### Type checking
We use mypy to typecheck some of our Python files:

```
$ bin/typecheck
```

### Protobufs
We use Protocol Buffers to serialise data to disk, you'd need the Protocol Buffers compilers
installed and then you can generate the code with:

```shell
$ bin/proto
```

## Adding a new Ruby version
Each Ruby version might have different offsets, naming, etc. This configuration lives in `version_specific_config.py`. Ideally we will be supporting some versions from 2.4 or greater. We do opt-in as we want to make sure `rbperf` works correctly and does not yield wrong stacks.

If you would like to add some major Ruby version, you can add it there, and running all the tests with that Ruby version (we'll make this easier in the future). If everything works, that's great! Send us a PR :)

If, unfortunately this does not work, it will require some investigation to find out why. This might be possibly due to a different offset. If that's the case, GDB will be your best ally!

Once this is done, if the offsets differ, a new Ruby interpreter can be added in `tests/rubies` and to the `tests/test_rbperf.py` lists of Ruby versions we want to test to ensure we won't regress.

Right this the process is quite cumbersome, sorry about this! We'll work on improving this in the future:

TODO(javierhonduco):
- publish some of the helpers and tips on how to debug rbperf
- add how to compile a new Ruby version
