English | [简体中文](README-CN.md)

# Alibaba CDN TCP Option Address

The TOA(TCP Option Address) is a TCP option in TCP header which contains the source IP address.
This kernel module is to obtain the IP address in TOA sent by Alibaba Cloud CDN servers.
It only supports IPv4 yet.

## Requirements

The kernel module supports kernel from 2.6.32 to 5.10.134.
To compile the kernel module, the environment requirements are as below:

- Kernel devel and related packages
- GCC compiler
- GNU make tool

## Installation

1. Git clone or download the source package
2. Enter the `src` directory and compile the kernel module

    ```
    cd src
    make
    ```

3. Load the kernel module

    ```
    sudo insmod tcp_toa.ko
    ```

## Uninstallation

```
sudo rmmod tcp_toa
```

---

## Changelog
Detailed changes for each release are documented in the [release notes](CHANGELOG).

## License
[GPLv2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt)

Copyright 2019-2020 Alibaba Group Holding Ltd.
