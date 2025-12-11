#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"

apt-get -y install curl ca-certificates wget xz-utils libsqlite3-dev libncurses-dev libreadline-dev pkgconf file

curl -o "${SOURCE_DIR}/util-linux-2.41.2.tar.gz" https://www.kernel.org/pub/linux/utils/util-linux/v2.41/util-linux-2.41.2.tar.xz
cd "${BUILD_DIR}" && tar -xf "${SOURCE_DIR}/util-linux-2.41.2.tar.gz"
cd "${BUILD_DIR}/util-linux-2.41.2"
mkdir build-static && cd build-static
../configure --prefix=${INSTALL_DIR} --disable-shared --enable-static --disable-libmount --disable-lslogins
sed -i 's/-fsigned-char/--static -lm -lncurses -fsigned-char/g' Makefile
sed -i 's/^READLINE_LIBS = -lreadline$/READLINE_LIBS = -lreadline -ltinfo/' Makefile
sed -i 's/-lsqlite3/-lsqlite3 -lm/g' Makefile
make -j 8
make install

strip_elf_files "$INSTALL_DIR/sbin"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" util-linux-linux-$(uname -m).tar.gz


