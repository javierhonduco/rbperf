# Investigation example using rbperf

At its core, `rbperf` is a tool that allows us to understand better what our Ruby code is doing. While it was originally develop for performance analysis, it can be used to increase the general observability of our application.

Let's imagine that we'd be interested in knowing where exceptions are raised in a Hello World [Rails](https://rubyonrails.org/) app

## Gathering the data

Ruby has a USDT (User Statically-Defined Tracepoint) probe for [`raise`](https://github.com/ruby/ruby/blob/afd84c5/doc/dtrace_probes.rdoc), so let's attach to it and get data for a couple of seconds

First, let's find out the Process Identifier (PID) of our Rails server:
```
$ ps aux | grep '[m]y_rails'
javierh+ 12774  0.5  0.5 1746120 123100 pts/4  Sl+  May15  36:51 puma 4.3.3 (tcp://localhost:3000) [my_rails]
```

Awesome, the PID for our Rails Hello World, unimaginatively named "my_rails" is `12774`!

Let's trace the `raise` USDT with:
```
$ sudo bin/rbperf record --pid=12774 event --usdt=raise
Tracing usdt:raise
Profiling pid: 12774 (Ruby 2.6.4) with addr: 0x7f6bd136a920
^CProcessed 132 events, lost 0 events, lost stacks 0, incomplete: 0, written: 132
Profile written to rbperf-2020-05-20T18:56:11.data
```

(the meaning of the second to last line can be found in the [Tutorial](https://github.com/facebookexperimental/rbperf/blob/master/docs/tutorial.md), but the important thing is that now we have 132 stacks on disk, awesome!)

## Generating a useful visualisation

With the output name we got above:

```
$ sudo bin/rbperf report --input rbperf-2020-05-20T18:56:11.data --output /tmp/rails_raise --format=flamegraph
Saved output to /tmp/rails_raise
```

![Screenshot of the `raise` Icicle](https://github.com/facebookexperimental/rbperf/blob/master/docs/raise_flamegraph.png)

Now can see where `raise` is called and how often, in relative terms, even if we don't have much context on this codebase! :)
