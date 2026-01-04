#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt-get -y install curl ca-certificates wget xz-utils libssl-dev libncurses-dev autoconf git libwrap0-dev libreadline-dev

cd "${SOURCE_DIR}"
git clone http://repo.or.cz/socat.git

cd "${SOURCE_DIR}/socat"
git clean -fdx
autoconf
LDFLAGS="-static" ./configure --prefix="${INSTALL_DIR}" --enable-openssl-base --enable-openssl-method --enable-resolve --enable-fips
make -j 4
strip -s "socat"
mkdir -p "${INSTALL_DIR}/bin" && mv "socat" "${INSTALL_DIR}/bin/socat"

strip_elf_files "$INSTALL_DIR/sbin"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" socat-latest-linux-${ARCH}.tar.gz