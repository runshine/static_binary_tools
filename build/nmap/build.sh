#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

VERSION="7.98"
PACKAGE="nmap"
EXT="tar.bz2"
apt-get -y install curl ca-certificates wget xz-utils libssl-dev libncurses-dev autoconf git libwrap0-dev libreadline-dev flex bison  liblua5.3-dev liblua5.4-dev libpcre2-dev libz-dev libzstd-dev bzip2 libpcap-dev libssh-dev liblinear-dev

curl -o "${SOURCE_DIR}/${PACKAGE}-${VERSION}.${EXT}" "https://nmap.org/dist/${PACKAGE}-${VERSION}.${EXT}"
[ -d "${BUILD_DIR}/${PACKAGE}-${VERSION}" ] && rm -rf "${PACKAGE}-${VERSION}"
cd "${BUILD_DIR}/" && tar -xf "${SOURCE_DIR}/${PACKAGE}-${VERSION}.${EXT}"
rm -f "${SOURCE_DIR}/${PACKAGE}-${VERSION}.${EXT}"

cd "${BUILD_DIR}/${PACKAGE}-${VERSION}"
CFLAGS=-static LDFLAGS="-static -lm" ./configure --prefix=${INSTALL_DIR} --disable-shared --enable-static
make install

strip_elf_files "$INSTALL_DIR/sbin"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" nmap-linux-${ARCH}.tar.gz
