#!/bin/bash

set -e

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt update && apt-get -y install curl wget unzip nodejs npm node-typescript

npm install vite

VERSION="latest"

cd /build/frontend
if [ -f package-lock.json ]; then npm ci; else npm install; fi
npm run build
cp -R dist ../nacos/static

cd /build

echo "aarch64" > nacos/.arch
tar -czvf "${INSTALL_DIR}/nacos_client-${VERSION}-linux-aarch64.tar.gz" nacos
echo "x86_64" > nacos/.arch
tar -czvf "${INSTALL_DIR}/nacos_client-${VERSION}-linux-x86_64.tar.gz" nacos
echo "armhf" > nacos/.arch
tar -czvf "${INSTALL_DIR}/nacos_client-${VERSION}-linux-armhf.tar.gz" nacos
echo "armel" > nacos/.arch
tar -czvf "${INSTALL_DIR}/nacos_client-${VERSION}-linux-armel.tar.gz" nacos
echo "riscv64" > nacos/.arch
tar -czvf "${INSTALL_DIR}/nacos_client-${VERSION}-linux-riscv64.tar.gz" nacos
