#!/bin/bash

set -e
show_error() {
    echo "error: $1" >&2
}
show_success() {
    echo "success: $1"
}


MAJOR=5
for MINOR in {0..19}; do

    echo "start Linux kernel version linux-${MAJOR}.${MINOR}"

    echo "downloading Linux kernel ..."
    # Not applicable to versions below kernel 3.0
    wget -q https://mirrors.edge.kernel.org/pub/linux/kernel/v${MAJOR}.x/linux-${MAJOR}.${MINOR}.tar.xz || { show_error "download failed"; return 1; }
    tar -xf linux-${MAJOR}.${MINOR}.tar.xz || { show_error "decompress failed"; return 1; }
    cd linux-${MAJOR}.${MINOR} || { show_error "cannot cd linux-${MAJOR}.${MINOR}"; return 1; }
    show_success "decompress success"

    echo "configure make file..."
    make allyesconfig > /dev/null 2>&1 || { show_error "configure failed"; return 1; }
    show_success "configure success"

    echo "start compile linux kernel..."
    if make -s -j$(nproc); then
        show_success "linux kernel ${MAJOR}.${MINOR} compile success"
    else
        show_error "linux kernel ${MAJOR}.${MINOR} compile failed"
        return 1
    fi

    cd ..
    show_success "linux kernel ${MAJOR}.${MINOR} process success"
done