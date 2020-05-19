# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from setuptools import setup, find_packages

setup(
    name="rbperf",
    version="0.1.0",
    author="Javier Honduvilla Coto",
    author_email="javierhonduco@gmail.com",
    packages=find_packages(),
    entry_points={"console_scripts": ["rbperf = cli:main"],},
    package_data={"rbperf": ["bpf/*", "vendor/*.pl"]},
    include_package_data=True,
    url="https://github.com/facebookexperimental/rbperf",
    license="LICENSE.txt",
    description="A Ruby BPF profiler",
    long_description="A Ruby BPF profiler",
    install_requires=["protobuf"],
    extras_require={"dev": ["mypy"]},
)
