#!/bin/sh
# SPDX-License-Identifier: BSD 2-Clause license

bpftool cgroup detach /sys/fs/cgroup/ sock_ops name toa_parse
bpftool cgroup detach /sys/fs/cgroup/ getpeername4 name toa_peername4
bpftool cgroup detach /sys/fs/cgroup/ getpeername6 name toa_peername6
rm -rf /sys/fs/bpf/toa