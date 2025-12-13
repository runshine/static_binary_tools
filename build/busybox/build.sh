#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

VERSION="1.37.0"
PACKAGE="busybox"
EXT="tar.bz2"
apt-get -y install curl ca-certificates wget xz-utils libssl-dev libncurses-dev autoconf git libwrap0-dev libreadline-dev flex bison bzip2 libz-dev

curl -o "${SOURCE_DIR}/${PACKAGE}-${VERSION}.${EXT}" "https://busybox.net/downloads/${PACKAGE}-${VERSION}.${EXT}"
[ -d "${BUILD_DIR}/${PACKAGE}-${VERSION}" ] && rm -rf "${PACKAGE}-${VERSION}"
cd "${BUILD_DIR}/" && tar -xf "${SOURCE_DIR}/${PACKAGE}-${VERSION}.${EXT}"
rm -f "${SOURCE_DIR}/${PACKAGE}-${VERSION}.${EXT}"

cd "${BUILD_DIR}/${PACKAGE}-${VERSION}"
make defconfig
sed -i 's/CONFIG_TC=y/# CONFIG_TC is not set/g' .config
make LDFLAGS="-static" -j 8
mkdir -p "${INSTALL_DIR}/bin" && cp "busybox" "${INSTALL_DIR}/bin/busybox"

strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" busybox-linux-${ARCH}.tar.gz