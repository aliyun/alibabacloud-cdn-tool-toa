#!/bin/sh
# SPDX-License-Identifier: BSD 2-Clause license

set -e

fsys=$(stat -fc %T /sys/fs/cgroup/)

if [ "$fsys" != "cgroup2fs" ]; then
    echo "Error, please open cgroupv2 first!"
    exit 1
fi

bpftool prog loadall ./toa-kern.o /sys/fs/bpf/toa
bpftool cgroup attach /sys/fs/cgroup/ sock_ops name toa_parse multi
bpftool cgroup attach /sys/fs/cgroup/ getpeername4 name toa_peername4 multi
bpftool cgroup attach /sys/fs/cgroup/ getpeername6 name toa_peername6 multi