#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"

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
