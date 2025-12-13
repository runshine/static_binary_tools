#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

VERSION="9.1.1975"
PACKAGE="vim"
EXT="tar.gz"
apt-get -y install curl ca-certificates wget xz-utils libssl-dev libncurses-dev autoconf git libwrap0-dev libreadline-dev flex bison  libpcre2-dev libz-dev libzstd-dev bzip2 libpcap-dev libssh-dev liblinear-dev

curl -L -o "${SOURCE_DIR}/${PACKAGE}-${VERSION}.${EXT}" "https://github.com/${PACKAGE}/${PACKAGE}/archive/refs/tags/v${VERSION}.${EXT}"
[ -d "${BUILD_DIR}/${PACKAGE}-${VERSION}" ] && rm -rf "${PACKAGE}-${VERSION}"
cd "${BUILD_DIR}/" && tar -xf "${SOURCE_DIR}/${PACKAGE}-${VERSION}.${EXT}"
rm -f "${SOURCE_DIR}/${PACKAGE}-${VERSION}.${EXT}"

cd "${BUILD_DIR}/${PACKAGE}-${VERSION}"
CFLAGS=-static LDFLAGS="-static" ./configure --prefix=${INSTALL_DIR}
make install

strip_elf_files "$INSTALL_DIR/sbin"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" vim-linux-${ARCH}.tar.gz
