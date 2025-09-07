#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"

VERSION="1.10.5"
PACKAGE="libpcap"
apt-get -y install curl ca-certificates wget xz-utils libssl-dev libncurses-dev autoconf git libwrap0-dev libreadline-dev flex bison

curl -o "${SOURCE_DIR}/${PACKAGE}-${VERSION}.tar.xz" "https://www.tcpdump.org/release/${PACKAGE}-${VERSION}.tar.xz"
[ -d "${BUILD_DIR}/${PACKAGE}-${VERSION}" ] && rm -rf "${PACKAGE}-${VERSION}"
mkdir "${BUILD_DIR}/" && tar -xf "${SOURCE_DIR}/${PACKAGE}-${VERSION}.tar.xz"
rm -f "${SOURCE_DIR}/${PACKAGE}-${VERSION}.tar.xz"

cd "${BUILD_DIR}/${PACKAGE}-${VERSION}"
LDFLAGS='-static' ./configure --enable-remote --prefix="${INSTALL_DIR}" --disable-shared
make -j 4

strip -s "./rpcapd/rpcapd"
mkdir -p  "${INSTALL_DIR}/bin"
mv "./rpcapd/rpcapd" "${INSTALL_DIR}/bin/rpcapd-linux-$(uname -m)"

