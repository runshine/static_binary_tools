#!/bin/bash

set -e

TZ=Europe/London
HOME_SPACE="$(cd `dirname $0`;pwd)/"

mkdir -p "${HOME_SPACE}/source"
mkdir -p "${HOME_SPACE}/build"
mkdir -p "${HOME_SPACE}/install"

SOURCE_DIR="${HOME_SPACE}/source"
BUILD_DIR="${HOME_SPACE}/build"
INSTALL_DIR="${HOME_SPACE}/install"

apt install -qq -y git gnupg curl autoconf libssl-dev pkg-config bison flex

cd ${SOURCE_DIR}
git clone https://github.com/iproute2/iproute2.git
cd iproute2

LDFLAGS="-static" PKG_CONFIG="pkg-config --static" ./configure --prefix ${INSTALL_DIR} --disable-shared --enable-static
make -j4 V=1 LDFLAGS="-static"
mkdir -p ${BUILD_DIR}/bin
cp bridge/bridge ${BUILD_DIR}/bin/bridge-linux-$(uname -m)
cp bridge/ip ${BUILD_DIR}/bin/ip-linux-$(uname -m)
