# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import sys
import argparse
import os

# TODO(javierhonduco): Rethink vendorised bcc

parent_dir = os.path.abspath(os.path.dirname(__file__))
vendor_dir = os.path.join(parent_dir, "../vendor")
sys.path.insert(0, vendor_dir)

from rbperf import (
    RbperfPerfEvent,
    RbperfTracepoint,
    RbperfUSDT,
)
from handlers import CompactHandler
from storage import CompactProtobufReader
from utils import is_root
from reporters import stdout_reporter, flamegraph_reporter, folded_reporter


EVERY_MILLION_EVENTS = 10 ** 6


def perform_checks():
    # TODO(javierhonduco): We can do more checks
    # - kernel version
    # - libbcc version
    # - sample bpf programs to probe for features
    if not is_root():
        print("You need root to use rbperf, sorry!")
        sys.exit(1)


def arg_parser():
    parser = argparse.ArgumentParser()

    subparser = parser.add_subparsers(dest="subparser_name")
    parser_record = subparser.add_parser("record")
    parser_record.add_argument("-p", "--pid", type=int, nargs="+")
    parser_record.add_argument("-b", "--bpf-progs", type=int, required=False)

    subparser_record = parser_record.add_subparsers(dest="record_subparser")
    parser_cpu = subparser_record.add_parser("cpu")
    parser_cpu.add_argument("--period", type=int, default=EVERY_MILLION_EVENTS)
    parser_event = subparser_record.add_parser("event")

    event_type = parser_event.add_mutually_exclusive_group(required=True)
    event_type.add_argument("--usdt", action="store")
    event_type.add_argument("--tracepoint", action="store")

    parser_report = subparser.add_parser("report")
    parser_report.add_argument("--input", type=str, required=True)
    parser_report.add_argument("--output", type=str, required=True)
    parser_report.add_argument(
        "--format", type=str, required=True, choices=("flamegraph", "folded", "stdout")
    )
    return parser


def main():
    perform_checks()
    parser = arg_parser()
    args = parser.parse_args()

    if args.subparser_name == "record":
        pids = args.pid
        bpf_programs_count = args.bpf_progs
        profile_type = args.record_subparser

        handler = CompactHandler()
        if profile_type == "cpu":
            sample_period = args.period
            print(f"Sampling every {sample_period:,} CPU cycles")
            result = (
                RbperfPerfEvent(
                    pids=pids,
                    sample_handler=handler,
                    bpf_programs_count=bpf_programs_count,
                )
                .profile(sample_period=sample_period)
                .poll()
            )
        elif profile_type == "event":
            if args.tracepoint:
                print(f"Tracing tracepoint:{args.tracepoint}")
                result = (
                    RbperfTracepoint(
                        pids=pids,
                        sample_handler=handler,
                        bpf_programs_count=bpf_programs_count,
                    )
                    .trace(args.tracepoint)
                    .poll()
                )
            elif args.usdt:
                print(f"Tracing usdt:{args.usdt}")
                result = (
                    RbperfUSDT(
                        usdt_name=args.usdt,
                        pids=pids,
                        sample_handler=handler,
                        bpf_programs_count=bpf_programs_count,
                    )
                    .trace()
                    .poll()
                )
        else:
            print("usage: rbperf record [...] {cpu,event}")
            sys.exit(1)

        print(result)
        print(f"Profile written to {result.filename}")

    elif args.subparser_name == "report":
        input_file_path = args.input
        output_file_path = args.output
        output_format = args.format

        with open(input_file_path, "rb") as input_file:
            proto = CompactProtobufReader(input_file)

            if output_format == "stdout":
                stdout_reporter(proto)
            elif output_format == "flamegraph":
                flamegraph_reporter(proto, output_file_path)
            elif output_format == "folded":
                folded_reporter(proto, output_file_path)

        print(f"Saved output to {output_file_path}")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
