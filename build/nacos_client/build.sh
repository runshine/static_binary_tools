#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt update && apt-get -y install curl wget unzip

VERSION="latest"

tar -czvf "${INSTALL_DIR}/nacos_client-${VERSION}-linux-aarch64.tar.gz" nacos
tar -czvf "${INSTALL_DIR}/nacos_client-${VERSION}-linux-x86_64.tar.gz" nacos
tar -czvf "${INSTALL_DIR}/nacos_client-${VERSION}-linux-armhf.tar.gz" nacos
tar -czvf "${INSTALL_DIR}/nacos_client-${VERSION}-linux-armel.tar.gz" nacos
tar -czvf "${INSTALL_DIR}/nacos_client-${VERSION}-linux-riscv64.tar.gz" nacos
