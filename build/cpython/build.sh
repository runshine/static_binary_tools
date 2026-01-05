#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt update && apt-get -y install curl wget

VERSION="3.12.11"
PYTHON_AARCH64="https://github.com/astral-sh/python-build-standalone/releases/download/20250723/cpython-3.12.11+20250723-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz"
PYTHON_ARMHF="https://github.com/astral-sh/python-build-standalone/releases/download/20250828/cpython-3.12.11+20250828-armv7-unknown-linux-gnueabihf-install_only.tar.gz"
PYTHON_ARMEL="https://github.com/astral-sh/python-build-standalone/releases/download/20250828/cpython-3.12.11+20250828-armv7-unknown-linux-gnueabi-install_only.tar.gz"
PYTHON_X64="https://github.com/astral-sh/python-build-standalone/releases/download/20250723/cpython-3.12.11+20250723-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
PYTHON_RISCV64="https://github.com/astral-sh/python-build-standalone/releases/download/20250723/cpython-3.12.11+20250723-riscv64-unknown-linux-gnu-install_only.tar.gz"
ARCH="$(uname -m)"
echo "CURRENT_ARCH: $ARCH"
if [ "$ARCH" = "aarch64" ];then
  URL="${PYTHON_AARCH64}"
elif [ "$ARCH" = "x86_64" ]; then
  URL="${PYTHON_X64}"
elif [ "$ARCH" = "armv8l" ] || [ "$ARCH" = "armv7l" ] || [ "$ARCH" = "armv7" ] ; then
  if [ -L "/lib/ld-linux.so.3" ] || [ -f "/lib/ld-linux.so.3" ];then
    URL="${PYTHON_ARMEL}"
    ARCH="armel"
  else
    URL="${PYTHON_ARMHF}"
    ARCH="armhf"
  fi
elif [ "$ARCH" = "riscv64" ] ||  [ "$ARCH" = "riscv64v" ];then
    URL="${PYTHON_RISCV64}"
fi

if [ "x${ARCH}" = "x" ] || [ "x${URL}" = "x" ];then
  echo "unsupport current arch: $ARCH"
  exit 255
fi

download() {
    url=$1
    target=$2
    if [ -f "$target" ];then
      return
    fi
    wget "${url}" -O "$target" || curl -L "${url}" -o "$target"
    if [ ! -f "$target" ];then
      echo "$(date): file: $target download failed --> $url"
    else
      echo "$(date): file: $target download success"
    fi
}

if [ -f "$URL" ];then
  cp "$URL" "${SOURCE_DIR}/cpython.tar.gz"
else
  download "$URL" "${SOURCE_DIR}/cpython.tar.gz"
fi

cd "${SOURCE_DIR}"

if [ -f "cpython.tar.gz" ];then
  tar -zxvf "cpython.tar.gz"
    "./python/bin/pip" install -r "/build/require.txt"
else
  echo "download failed"
  exit 255
fi

rm -rf "cpython.tar.gz"
cd "${SOURCE_DIR}/python"
tar -czvf "../cpython-${VERSION}-linux-$ARCH.tar.gz" .
cd "${SOURCE_DIR}"
rm -rf python

mv "cpython-${VERSION}-linux-$ARCH.tar.gz" "$INSTALL_DIR/"
echo "done"


