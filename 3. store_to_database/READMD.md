# Linux Kernel Database Creator

## Purpose

This Python script is designed to create a MySQL database of Linux kernel source code (.c files) and their corresponding
compiled object files (.o files).

## Environment Setup

### Python 3.10.14

## Features

- Scans Linux kernel source directories for pairs of .c and .o files.
- Reads the content of both source and object files
- Stores file paths, names, C code content, and compiled object code in a MySQL database
- Uses connection pooling for efficient database operations
- Provides progress bars for long-running operations

## Configuration

set up .env file

## Usage

Run the script with Python:

```cmd
python script_name.py
```

## Database Structure

- id: Auto-incrementing primary key
- code_path: Path to the file within the kernel source tree
- filename: Name of the file (without extension)
- c_code: Content of the C source file
- o_code: Binary content of the object file



















