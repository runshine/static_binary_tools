#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"

VERSION=2409

curl -o "${SOURCE_DIR}/7z-${VERSION}-src.tar.xz" "https://www.7-zip.org/a/7z${VERSION}-src.tar.xz"
[ -d "${BUILD_DIR}/7z-${VERSION}" ] && rm -rf "${BUILD_DIR}/7z-${VERSION}"
mkdir "${BUILD_DIR}/7z-${VERSION}"
cd "${BUILD_DIR}/7z-${VERSION}" && tar -xf "${SOURCE_DIR}/7z-${VERSION}-src.tar.xz"
rm -f "${SOURCE_DIR}/7z-${VERSION}-src.tar.xz"

cd "${BUILD_DIR}/7z-${VERSION}/CPP/7zip/Bundles/Alone2"
make -j4 CFLAGS_BASE_LIST="-c -static -D_7ZIP_AFFINITY_DISABLE=1 -DZ7_AFFINITY_DISABLE=1 -D_GNU_SOURCE=1" MY_ASM=uasm MY_ARCH="-static" CFLAGS_WARN_WALL="-Wall -Wextra" -f ../../cmpl_gcc.mak
strip "${BUILD_DIR}/7z-${VERSION}/CPP/7zip/Bundles/Alone2/b/g/7zz"
mkdir -p  "${INSTALL_DIR}/bin"
mv "${BUILD_DIR}/7z-${VERSION}/CPP/7zip/Bundles/Alone2/b/g/7zz" "${INSTALL_DIR}/bin/7zz-linux-$(uname -m)"

