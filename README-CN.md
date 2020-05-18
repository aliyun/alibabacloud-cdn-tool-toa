[English](README.md) | 简体中文

# Alibaba CDN TCP Option Address

TOA(TCP Option Address)是一个TCP协议选项，包含于TCP协议头中，携带有源地址信息。
本内核模块用于解析并获取TOA中的源地址，且只适用于阿里云CDN发送的TOA。
本内核模块当前仅支持IPv4。

## 环境要求

本内核模块当前仅支持Linux v2.6.32-v3.10.0版本内核，对应的发行版例如CentOS 6.5/7.2/7.7。
在开始编译前，请确保您已安装:
- Kernel devel安装包和其他相关的安装包
- GCC编译器
- GNU make工具

## 安装

1. 从GitHub克隆源码或下载源码压缩包并解压
2. 进入`src`目录编译内核模块

    ```
    cd src
    make
    ```

3. 加载内核模块

    ```
    sudo insmod tcp_toa.ko
    ```

## 卸载

```
sudo rmmod tcp_toa
```

---

## 发行说明
每个版本的详细更改记录在[发行说明](CHANGELOG)中。

## 许可证
[GPLv2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt)

版权所有 2019-2020 阿里巴巴集团
