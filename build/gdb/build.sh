#!/bin/bash

#https://github.com/guyush1/gdb-static.git
#https://github.com/guyush1/gdb-static/releases/download/v17.1-static/gdb-static-full-aarch64.tar.gz
#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

sudo apt update && sudo apt-get -y install curl

VERSION="v17.1"
GDB_AARCH64="https://github.com/guyush1/gdb-static/releases/download/${VERSION}-static/gdb-static-full-aarch64.tar.gz"
GDB_ARMHF="https://github.com/guyush1/gdb-static/releases/download/${VERSION}-static/gdb-static-full-arm.tar.gz"
GDB_ARMEL="https://github.com/guyush1/gdb-static/releases/download/${VERSION}-static/gdb-static-full-arm.tar.gz"
GDB_X64="https://github.com/guyush1/gdb-static/releases/download/${VERSION}-static/gdb-static-full-x86_64.tar.gz"


mkdir -p "$INSTALL_DIR/bin"
cd "$INSTALL_DIR"
curl -L -o "$INSTALL_DIR/bin/gdb.tar.gz" "${GDB_AARCH64}"
cd "$INSTALL_DIR/bin" && tar -xf gdb.tar.gz && rm -rf gdb.tar.gz
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" gdb-${VERSION}-linux-aarch64.tar.gz
mv gdb-${VERSION}-linux-aarch64.tar.gz "$INSTALL_DIR/../"

mkdir -p "$INSTALL_DIR/bin"
cd "$INSTALL_DIR"
curl -L -o "$INSTALL_DIR/bin/gdb.tar.gz" "${GDB_ARMHF}"
cd "$INSTALL_DIR/bin" && tar -xf gdb.tar.gz && rm -rf gdb.tar.gz
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" gdb-${VERSION}-linux-armhf.tar.gz
mv gdb-${VERSION}-linux-armhf.tar.gz "$INSTALL_DIR/../"

mkdir -p "$INSTALL_DIR/bin"
cd "$INSTALL_DIR"
curl -L -o "$INSTALL_DIR/bin/gdb.tar.gz" "${GDB_ARMEL}"
cd "$INSTALL_DIR/bin" && tar -xf gdb.tar.gz && rm -rf gdb.tar.gz
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" gdb-${VERSION}-linux-armel.tar.gz
mv gdb-${VERSION}-linux-armel.tar.gz "$INSTALL_DIR/../"

mkdir -p "$INSTALL_DIR/bin"
cd "$INSTALL_DIR"
curl -L -o "$INSTALL_DIR/bin/gdb.tar.gz" "${GDB_X64}"
cd "$INSTALL_DIR/bin" && tar -xf gdb.tar.gz && rm -rf gdb.tar.gz
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" gdb-${VERSION}-linux-x86_64.tar.gz
mv gdb-${VERSION}-linux-x86_64.tar.gz "$INSTALL_DIR/../"

cd "$INSTALL_DIR"
mv ../gdb-${VERSION}-linux-aarch64.tar.gz "$INSTALL_DIR/"
mv ../gdb-${VERSION}-linux-armhf.tar.gz "$INSTALL_DIR/"
mv ../gdb-${VERSION}-linux-armel.tar.gz "$INSTALL_DIR/"
mv ../gdb-${VERSION}-linux-x86_64.tar.gz "$INSTALL_DIR/"

