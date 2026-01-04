#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt install -y git gnupg curl autoconf  libssl-dev zlib1g-dev libssh2-1-dev clang llvm pkg-config libzstd-dev
pkg-config --modversion openssl
CURL_VERSION='8.11.0'
export CC=clang

curl -o ${HOME_SPACE}/source/curl-${CURL_VERSION}.tar.gz https://curl.se/download/curl-${CURL_VERSION}.tar.gz
mkdir -p "${BUILD_DIR}" && cd "${BUILD_DIR}" && tar -zxvf ${HOME_SPACE}/source/curl-${CURL_VERSION}.tar.gz

cd curl-${CURL_VERSION}/

./configure --prefix=${INSTALL_DIR} --disable-shared --enable-static --disable-ldap --enable-ipv6 --enable-unix-sockets --with-ssl=$(pkg-config --variable=prefix  openssl) --with-libssh2 --disable-docs --disable-manual --without-libpsl

sed -i "s/-lzstd/-lzstd -latomic/g" src/Makefile

make -j4 V=1 LDFLAGS="-static -all-static"

# binary is ~13M before stripping, 2.6M after
strip src/curl

# print out some info about this, size, and to ensure it's actually fully static
ls -lah src/curl
# exit with error code 1 if the executable is dynamic, not static
ldd src/curl && exit 1 || true

./src/curl -V

mkdir -p ${INSTALL_DIR}/bin/ && cp src/curl ${INSTALL_DIR}/bin/curl

strip_elf_files "$INSTALL_DIR/sbin"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" curl-v8.11.0-linux-${ARCH}.tar.gz