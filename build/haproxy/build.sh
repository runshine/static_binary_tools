#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

VERSION="3.3.0"
PACKAGE="haproxy"
apt-get -y install curl ca-certificates wget xz-utils libssl-dev libncurses-dev autoconf git libwrap0-dev libreadline-dev flex bison  liblua5.3-dev liblua5.4-dev libpcre2-dev

curl -o "${SOURCE_DIR}/${PACKAGE}-${VERSION}.tar.gz" "https://www.haproxy.org/download/3.3/src/haproxy-3.3.0.tar.gz"
[ -d "${BUILD_DIR}/${PACKAGE}-${VERSION}" ] && rm -rf "${PACKAGE}-${VERSION}"
cd "${BUILD_DIR}/" && tar -xf "${SOURCE_DIR}/${PACKAGE}-${VERSION}.tar.gz"
rm -f "${SOURCE_DIR}/${PACKAGE}-${VERSION}.tar.gz"

cd "${BUILD_DIR}/${PACKAGE}-${VERSION}"
sed -i 's/CC = cc/CC = cc -static -lz/g' Makefile
make -j 8 TARGET=linux-glibc CFLAGS=-static PREFIX="${INSTALL_DIR}" USE_OPENSSL=1 USE_QUIC=1 USE_QUIC_OPENSSL_COMPAT=1 USE_LUA=0 USE_PCRE2=1 install

strip_elf_files "$INSTALL_DIR/sbin"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" haproxy-linux-${ARCH}.tar.gz
