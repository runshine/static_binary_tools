#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"

apt-get -y install curl ca-certificates wget xz-utils

curl -o "${SOURCE_DIR}/strace-6.16.tar.xz" https://strace.io/files/6.16/strace-6.16.tar.xz
cd "${BUILD_DIR}" && tar -xf "${SOURCE_DIR}/strace-6.16.tar.xz"
cd "${BUILD_DIR}/strace-6.16"
LDFLAGS='-static -pthread' ./configure --prefix=${INSTALL_DIR} --disable-shared --enable-static --enable-mpers=no
LDFLAGS='-static -all-static -pthread' make -j4
make install

