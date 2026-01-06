#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

sudo apt update && sudo apt-get -y install curl

VERSION="17.5.2"
FRIDA_SERVER_AARCH64="https://github.com/frida/frida/releases/download/17.5.2/frida-server-17.5.2-linux-arm64.xz"
FRIDA_SERVER_ARMHF="https://github.com/frida/frida/releases/download/17.5.2/frida-server-17.5.2-linux-armhf.xz"
FRIDA_SERVER_X64="https://github.com/frida/frida/releases/download/17.5.2/frida-server-17.5.2-linux-x86_64.xz"


cd "$BUILD_DIR"
curl -L -o "$BUILD_DIR/frida-server.xz" "${FRIDA_SERVER_AARCH64}"
xz -d frida-server.xz
mkdir -p $BUILD_DIR/bin/ && mv frida-server* $BUILD_DIR/bin/frida-server
strip_elf_files "$BUILD_DIR/bin/"
package_release_tar "${BUILD_DIR}" frida_server-${VERSION}-linux-aarch64.tar.gz
cd "$BUILD_DIR" && rm * -rf


cd "$BUILD_DIR"
curl -L -o "$BUILD_DIR/frida-server.xz" "${FRIDA_SERVER_ARMHF}"
xz -d frida-server.xz &&
mkdir -p $BUILD_DIR/bin/ && mv frida-server* $BUILD_DIR/bin/frida-server
strip_elf_files "$BUILD_DIR/bin/"
package_release_tar "${BUILD_DIR}" frida_server-${VERSION}-linux-armhf.tar.gz
cd "$BUILD_DIR" && rm * -rf


cd "$BUILD_DIR"
curl -L -o "$BUILD_DIR/frida-server.xz" "${FRIDA_SERVER_X64}"
xz -d frida-server.xz
mkdir -p $BUILD_DIR/bin/ && mv frida-server* $BUILD_DIR/bin/frida-server
strip_elf_files "$BUILD_DIR/bin/"
package_release_tar "${BUILD_DIR}" frida_server-${VERSION}-linux-x86_64.tar.gz
cd "$BUILD_DIR" && rm * -rf

mv ../*.tar.gz ${INSTALL_DIR}/

echo "done"

