#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt-get -y install curl ca-certificates wget libssl-dev autoconf make cmake xz-utils flex bison

curl -o "${SOURCE_DIR}/libpcap-1.10.5.tar.xz" https://www.tcpdump.org/release/libpcap-1.10.5.tar.xz
cd "${BUILD_DIR}" && tar -xf "${SOURCE_DIR}/libpcap-1.10.5.tar.xz"
cd "${BUILD_DIR}/libpcap-1.10.5"
./configure --prefix=/usr
make -j4 && make install

curl -o "${SOURCE_DIR}/tcpdump-4.99.5.tar.xz" https://www.tcpdump.org/release/tcpdump-4.99.5.tar.xz
cd "${BUILD_DIR}" && tar -xf "${SOURCE_DIR}/tcpdump-4.99.5.tar.xz"
cd "${BUILD_DIR}/tcpdump-4.99.5"
CFLAGS='-static -lssl' ./configure --prefix=${INSTALL_DIR}
make -j4 && make install

strip_elf_files "$INSTALL_DIR/sbin"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" tcpdump-v4.99.5-linux-${ARCH}.tar.gz