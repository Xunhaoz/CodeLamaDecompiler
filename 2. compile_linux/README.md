# Compile Kernel

## Purpose

In our project, compiling the Linux kernel to generate object files is a critical step, but it's often complex and
time-consuming. To simplify this process, we developed this script to automate the Linux kernel compilation.Also, We 
have completed a table that maps Linux distributions to the corresponding Linux kernel versions that can be compiled 
on each distribution.

## Environment Setup

### Host Machine: Ubuntu 18.04

Linux xunhaoz-ubuntu24 6.8.0-40-generic #40-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul 5 10:34:03 UTC 2024 x86_64 x86_64 x86_64
GNU/Linux

### Virtual Machine: KVM

QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1)
Copyright (c) 2003-2023 Fabrice Bellard and the QEMU Project developers

### Virtual Machine GUI: Virt-Manager

4.1.0

## Usage Instructions

1. [Install Virtual Machine](https://hackmd.io/@zlQHp-D8R3uG9eJTFh2iVA/HJtjHCAM9)
2. [Install Virtual Machine GUI](https://ivonblog.com/posts/ubuntu-virt-manager/)
3. [Download Ubuntu ISO](http://ftp.tku.edu.tw/ubuntu-releases/)
4. install tools
   ```shell
   sudo apt-get update
   sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev bc
   ```
5. run compile.sh

## Kernel Version Compatibility with Ubuntu

Different versions of the Linux kernel are typically compiled on specific Ubuntu versions due to several interconnected
factors. These include toolchain compatibility, system dependencies, Ubuntu-specific kernel modifications, and ABI
compatibility. Each Ubuntu release is optimized for certain kernel versions, ensuring stability, security, and proper
hardware support. While cross-version compilation is technically possible, it often leads to complications. Therefore,
matching the kernel version with the appropriate Ubuntu version for compilation is generally recommended to avoid
potential issues and ensure optimal functionality.

| Kernel Version  | Ubuntu Version |
|-----------------|----------------|
| 3.0 - 3.19      | 14.04          |
| 4.0 - 4.19      | 14.04          |
| 5.1, 5.3 - 5.7  | 14.04          |
| 5.2, 5.8 - 5.17 | 18.04          |
| 5.18 - 5.19     | 24.04          |
| 6.1 - 6.9       | 24.04          |

## Additional information

> ways to transfer files between host and guest

### Shared Folder via virtio-9p

[Virtio-9p Tutorial](https://ostechnix.com/setup-a-shared-folder-between-kvm-host-and-guest/)

### Shared Folder via virtiofs

same as virtio-9p, but with different mount command

```shell
mount -t virtiofs mount_tag /mnt/mount/path
```

### Shared Folder via sftp

[SFTP Tutorial](https://www.digitalocean.com/community/tutorials/how-to-use-sftp-to-securely-transfer-files-with-a-remote-server)
