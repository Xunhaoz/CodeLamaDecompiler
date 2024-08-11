# Decompile IDA

This Python script is designed to automate the process of decompiling Linux kernel object files (.o files). It reads
object files from a MySQL database, decompiles them using IDA Pro, and then stores the results back in the database.

## Environment

HOST: Ubuntu 24.04
KVM: QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1)

## Windows Container

windows [github](https://github.com/dockur/windows)

## Features

- Reads Linux kernel object files from a MySQL database
- Automatically decompiles object files using IDA Pro
- Extracts assembly code and pseudocode
- Stores decompilation results back in the MySQL database
- Utilizes multi-threading for improved efficiency

## Usage

1. Install Windows
2. Install IDA Pro 8.3
3. Copy scripts into windows via shared folder
4. Set up environment the variables
5. run worker.py


































