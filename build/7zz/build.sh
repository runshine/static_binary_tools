#!/bin/bash

set -e

VERSION=2409
TZ=Europe/London

mkdir -p /opt/source
mkdir -p /opt/build
mkdir -p /opt/install
curl -o /opt/source/7z-${VERSION}-src.tar.xz "https://www.7-zip.org/a/7z${VERSION}-src.tar.xz"
[ -d "/opt/build/7z-${VERSION}" ] && rm -rf "/opt/build/7z-${VERSION}"
mkdir /opt/build/7z-${VERSION}
cd /opt/build/7z-${VERSION} && tar -xf /opt/source/7z-${VERSION}-src.tar.xz
rm -f /opt/source/7z-${VERSION}-src.tar.xz

cd /opt/build/7z-${VERSION}/CPP/7zip/Bundles/Alone2
make CFLAGS_BASE_LIST="-c -static -D_7ZIP_AFFINITY_DISABLE=1 -DZ7_AFFINITY_DISABLE=1 -D_GNU_SOURCE=1" MY_ASM=uasm MY_ARCH="-static" CFLAGS_WARN_WALL="-Wall -Wextra" -f ../../cmpl_gcc.mak
strip /opt/build/7z-${VERSION}/CPP/7zip/Bundles/Alone2/b/g/7zz
mkdir -p /opt/install/bin/7zz
mv /opt/build/7z-${VERSION}/CPP/7zip/Bundles/Alone2/b/g/7zz /opt/install/bin/7zz

