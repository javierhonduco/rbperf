# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from typing import Dict
import subprocess
import io
import pkg_resources


def readable_reporter(proto, output_file_path: str) -> None:
    with open(output_file_path, "w") as output:
        for stack in proto.read_stacks():
            pid = stack.pid
            comm = stack.comm
            if stack.stack_status == 1:
                output.write("_warning_: this stack might be incomplete\n")
            for frame in stack.frames:
                output.write(
                    f"[{comm}][{pid}] {frame.path}:{frame.lineno} `{frame.method}`\n"
                )
            output.write("\n")


def flamegraph_reporter(proto, output_file_path: str) -> None:
    f = io.StringIO()

    folded: Dict[str, int] = {}
    for stack in proto.read_stacks():
        folded_stack = ";".join(
            [f"{frame.method} - {frame.path}" for frame in stack.frames]
        )
        if folded_stack in folded:
            folded[folded_stack] += 1
        else:
            folded[folded_stack] = 1

    for folded_frame, count in folded.items():
        f.write(f"{folded_frame} {count}\n")

    flamegraph_path = pkg_resources.resource_filename("rbperf", "vendor/flamegraph.pl")
    p = subprocess.Popen(
        [flamegraph_path, "--inverted"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    flamegraph_html = p.communicate(input=f.getvalue().encode())[0].decode()

    with open(output_file_path, "w") as output:
        output.write(flamegraph_html)


def folded_reporter(proto, output_file_path: str) -> None:
    folded: Dict[str, int] = {}
    for stack in proto.read_stacks():
        folded_stack = ";".join(
            [f"{frame.method} - {frame.path}" for frame in stack.frames]
        )
        if folded_stack in folded:
            folded[folded_stack] += 1
        else:
            folded[folded_stack] = 1

    with open(output_file_path, "w") as f:
        for folded_frame, count in folded.items():
            f.write(f"{folded_frame} {count}\n")
