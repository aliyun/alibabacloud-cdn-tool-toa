English | [简体中文](README-CN.md)

# Alibaba CDN TCP Option Address

The TOA(TCP Option Address) is a TCP option in TCP header which contains the source IP address.
This repository provides two TOA parsing methods：
1. Kernel module
2. Ebpf

The detail of the two parsing methods：
|  Parsing method   | IPV6  | OS | Kernel version |
|  ----  | ----  | ---- | ---- |
| Kernel module  | unsupport | CentOS 6.5/7.2/7.7/8.5/9, Anolis OS 7/8 | 2.6.32 - 5.14 |
| Ebpf  | support | CentOS 9, Anolis OS 8.9 | >= 5.10.134 |


This TOA parsing is to obtain the IP address in TOA only sent by Alibaba Cloud CDN servers.

## Kernel module
### Requirements

The kernel module supports kernel from 2.6.32 to 5.14. It only supports IPv4 yet.
To compile the kernel module, the environment requirements are as below:

- Kernel devel and related packages
- GCC compiler
- GNU make tool

### Installation

1. Git clone or download the source package
2. Enter the `toa-kmod` directory and compile the kernel module

    ```
    cd toa-kmod
    make
    ```

3. Load the kernel module

    ```
    sudo insmod tcp_toa.ko
    ```

### Uninstallation

```
sudo rmmod tcp_toa
```

## Ebpf
### Requirements

Ebpf prog supports kernel over v5.10.134. It supports both IPv4 and IPv6.
To compile the ebpf prog, the environment requirements are as below:

- libbpf devel
- Clang compiler
- llvm
- bpftool

### Installation

1. Git clone or download the source package
2. Enter the `toa-ebpf` directory and compile the kernel module

    ```
    cd toa-ebpf
    make
    ```

3. Load the kernel module

    ```
    sudo ./load.sh
    ```

### Uninstallation

```
sudo ./unload.sh
```

---

## Changelog
Detailed changes for each release are documented in the [release notes](CHANGELOG).

## License
[GPLv2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt)

Copyright 2019-2024 Alibaba Group Holding Ltd.
