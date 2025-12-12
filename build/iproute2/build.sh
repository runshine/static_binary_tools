#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"

apt install -y git gnupg curl autoconf libssl-dev pkg-config bison flex

cd ${SOURCE_DIR}
git clone https://github.com/iproute2/iproute2.git
cd iproute2

LDFLAGS="-static" PKG_CONFIG="pkg-config --static" ./configure --prefix ${INSTALL_DIR} --disable-shared --enable-static
make -j4 V=1 LDFLAGS="-static"
mkdir -p ${INSTALL_DIR}/bin
cp bridge/bridge ${INSTALL_DIR}/bin/bridge
cp ip/ip ${INSTALL_DIR}/bin/ip

strip_elf_files "$INSTALL_DIR/sbin"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" iproute2-linux-$(uname -m).tar.gz