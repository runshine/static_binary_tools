#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"

VERSION="2.45"
apt-get -y install curl ca-certificates wget xz-utils libssl-dev libncurses-dev autoconf git libwrap0-dev libreadline-dev zstd libz-dev

curl -o "${SOURCE_DIR}/binutils-${VERSION}.tar.zst" "https://ftp.gnu.org/gnu/binutils/binutils-${VERSION}.tar.zst"
[ -d "${BUILD_DIR}/binutils-${VERSION}" ] && rm -rf "${BUILD_DIR}/binutils-${VERSION}"
cd "${BUILD_DIR}/" && tar -xf "${SOURCE_DIR}/binutils-${VERSION}.tar.zst"
rm -f "${SOURCE_DIR}/binutils-${VERSION}.tar.zst"

cd "${BUILD_DIR}/binutils-${VERSION}"
LDFLAGS="-static" ./configure --prefix="${INSTALL_DIR}"
make -j 4 && make install



