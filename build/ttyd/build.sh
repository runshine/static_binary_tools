#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

sudo apt update && sudo apt-get -y install curl

VERSION="1.7.7"
TTYD_AARCH64="https://github.com/tsl0922/ttyd/releases/download/${VERSION}/ttyd.aarch64"
TTYD_ARMHF="https://github.com/tsl0922/ttyd/releases/download/${VERSION}/ttyd.armhf"
TTYD_ARMEL="https://github.com/tsl0922/ttyd/releases/download/${VERSION}/ttyd.arm"
TTYD_X64="https://github.com/tsl0922/ttyd/releases/download/${VERSION}/ttyd.x86_64"


mkdir -p "$INSTALL_DIR/bin"
cd "$INSTALL_DIR"
curl -L -o "$INSTALL_DIR/bin/ttyd" "${TTYD_AARCH64}"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" ttyd-linux-aarch64.tar.gz
mv ttyd-linux-aarch64.tar.gz "$INSTALL_DIR/../"

mkdir -p "$INSTALL_DIR/bin"
cd "$INSTALL_DIR"
curl -L -o "$INSTALL_DIR/bin/ttyd" "${TTYD_ARMHF}"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" ttyd-linux-armhf.tar.gz
mv ttyd-linux-armhf.tar.gz "$INSTALL_DIR/../"

mkdir -p "$INSTALL_DIR/bin"
cd "$INSTALL_DIR"
curl -L -o "$INSTALL_DIR/bin/ttyd" "${TTYD_ARMEL}"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" ttyd-linux-armel.tar.gz
mv ttyd-linux-armel.tar.gz "$INSTALL_DIR/../"

mkdir -p "$INSTALL_DIR/bin"
cd "$INSTALL_DIR"
curl -L -o "$INSTALL_DIR/bin/ttyd" "${TTYD_X64}"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" ttyd-linux-x86_64.tar.gz
mv ttyd-linux-x86_64.tar.gz "$INSTALL_DIR/../"

cd "$INSTALL_DIR"
mv ../ttyd-linux-aarch64.tar.gz "$INSTALL_DIR/"
mv ../ttyd-linux-armhf.tar.gz "$INSTALL_DIR/"
mv ../ttyd-linux-armel.tar.gz "$INSTALL_DIR/"
mv ../ttyd-linux-x86_64.tar.gz "$INSTALL_DIR/"

