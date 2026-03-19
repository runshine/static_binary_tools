#!/bin/bash

set -e

export TZ="Asia/Shanghai"

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt update && apt-get -y install curl wget unzip
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
\. "$HOME/.nvm/nvm.sh"
nvm install 24

VERSION_DATE=$(date +"%Y%m%d.%H%M%S")
YEAR=${VERSION_DATE:0:4}
MONTH=${VERSION_DATE:4:2}
DAY=${VERSION_DATE:6:2}
BUILD=${VERSION_DATE#*.}
VERSION_HUMAN="v${YEAR}.${MONTH}.${DAY} (build ${BUILD})"
VERSION_SEMVER="${YEAR}.$((10#${MONTH})).$((10#${DAY}))+${BUILD}"

cd /build
cat > nacos/version.json <<EOF
{
  "date": "${VERSION_DATE}",
  "human": "${VERSION_HUMAN}",
  "semver": "${VERSION_SEMVER}",
  "build_time": "$(date -Iseconds)",
  "build_tz": "${TZ}"
}
EOF
echo "build version date: ${VERSION_DATE}"
echo "build version human: ${VERSION_HUMAN}"
echo "build version semver: ${VERSION_SEMVER}"

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
