#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt-get -y install curl ca-certificates wget xz-utils

curl -o "${SOURCE_DIR}/strace-6.16.tar.xz" https://strace.io/files/6.16/strace-6.16.tar.xz
cd "${BUILD_DIR}" && tar -xf "${SOURCE_DIR}/strace-6.16.tar.xz"
cd "${BUILD_DIR}/strace-6.16"
LDFLAGS='-static -pthread' ./configure --prefix=${INSTALL_DIR} --disable-shared --enable-static --enable-mpers=no
LDFLAGS='-static -all-static -pthread' make -j4
make install

strip_elf_files "$INSTALL_DIR/sbin"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" strace-linux-${ARCH}.tar.gz