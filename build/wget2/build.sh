#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

VERSION="2.2.0"
PACKAGE="wget2"
EXT="tar.gz"
apt-get -y install curl ca-certificates wget xz-utils libssl-dev libncurses-dev autoconf git libwrap0-dev libreadline-dev flex bison  libpcre2-dev libz-dev libzstd-dev bzip2 libpcap-dev libssh-dev liblinear-dev

curl -L -o "${SOURCE_DIR}/${PACKAGE}-${VERSION}.${EXT}" "https://ftp.gnu.org/gnu/wget/${PACKAGE}-${VERSION}.${EXT}"
[ -d "${BUILD_DIR}/${PACKAGE}-${VERSION}" ] && rm -rf "${PACKAGE}-${VERSION}"
cd "${BUILD_DIR}/" && tar -xf "${SOURCE_DIR}/${PACKAGE}-${VERSION}.${EXT}"
rm -f "${SOURCE_DIR}/${PACKAGE}-${VERSION}.${EXT}"

cd "${BUILD_DIR}/${PACKAGE}-${VERSION}"
CFLAGS=--static LDFLAGS="--static" ./configure --prefix=${INSTALL_DIR}  --disable-shared --enable-static
sed -i "s/-lssl -lcrypto/-lssl -lcrypto -lzstd -lz/g" Makefile
sed -i "s/-lssl -lcrypto/-lssl -lcrypto -lzstd -lz/g" examples/Makefile
sed -i "s/-lssl -lcrypto/-lssl -lcrypto -lzstd -lz/g" src/Makefile
make install

strip_elf_files "$INSTALL_DIR/sbin"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" wget2-linux-${ARCH}.tar.gz
