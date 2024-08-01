[English](README.md) | 简体中文

# Alibaba CDN TCP Option Address

TOA(TCP Option Address)是一个TCP协议选项，包含于TCP协议头中，携带有源地址信息。
本仓库提供两种TOA解析方式：
1. 内核模块
2. Ebpf

两种解析方式的优缺点：
|  解析方式   | IPV6支持  | 支持系统 | 支持内核 |
|  ----  | ----  | ---- | ---- |
| 内核模块  | 不支持 | CentOS 6.5/7.2/7.7/8.5/9, Anolis OS 7/8 | 2.6.32 - 5.14 |
| ebpf  | 支持 | CentOS 9, Anolis OS 8.9 | >= 5.10.134 |

本仓库TOA解析只适用于阿里云CDN发送的TOA。

## 内核模块
### 环境要求

本内核模块支持内核版本从2.6.32到5.14。内核模块只支持解析IPv4。
在开始编译前，请确保您已安装:
- Kernel devel安装包和其他相关的安装包
- GCC编译器
- GNU make工具

### 安装

1. 从GitHub克隆源码或下载源码压缩包并解压
2. 进入`toa-kmod`目录编译内核模块

    ```
    cd toa-kmod
    make
    ```

3. 加载内核模块

    ```
    sudo insmod tcp_toa.ko
    ```

### 卸载

```
sudo rmmod tcp_toa
```

## Ebpf
### 环境要求

当前ebpf程序支持内核版本5.10.134及以上。ebpf程序支持解析IPv4和IPv6。
在开始编译前，请确保您已安装:
- libbpf devel
- Clang编译器
- llvm
- bpftool

### 安装

1. 从GitHub克隆源码或下载源码压缩包并解压
2. 进入`toa-ebpf`目录编译内核模块

    ```
    cd toa-ebpf
    make
    ```

3. 加载ebpf程序

    ```
    sudo ./load.sh
    ```

### 卸载

```
sudo ./unload.sh
```

---

## 发行说明
每个版本的详细更改记录在[发行说明](CHANGELOG)中。

## 许可证
[GPLv2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt)

版权所有 2019-2024 阿里巴巴集团
