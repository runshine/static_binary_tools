#!/bin/bash

set -e

TZ=Europe/London
HOME_SPACE="$(cd `dirname $0`;pwd)/"

mkdir -p "${HOME_SPACE}/source"
mkdir -p "${HOME_SPACE}/build"
mkdir -p "${HOME_SPACE}/install"

SOURCE_DIR="${HOME_SPACE}/source"
BUILD_DIR="${HOME_SPACE}/build"
INSTALL_DIR="${HOME_SPACE}/install"

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
