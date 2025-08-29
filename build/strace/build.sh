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

apt-get -y install curl ca-certificates wget

curl -o "${SOURCE_DIR}/strace-6.16.tar.xz" https://strace.io/files/6.16/strace-6.16.tar.xz
cd "${BUILD_DIR}" && tar -xf "${SOURCE_DIR}/strace-6.16.tar.xz"
cd "${BUILD_DIR}/strace-6.16"
LDFLAGS='-static -pthread' ./configure --prefix=${INSTALL_DIR} --disable-shared --enable-static --enable-mpers=no
LDFLAGS='-static -all-static -pthread' make -j4
make install

