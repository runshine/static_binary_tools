#!/bin/bash

set -e

TZ=Europe/London

if [ "x${HOME_SPACE}" = "x" ];then
  HOME_SPACE="$(cd `dirname $0`;pwd)/"
fi

[ -d "${HOME_SPACE}" ] || mkdir -p "${HOME_SPACE}"

SOURCE_DIR="${HOME_SPACE}/source"
BUILD_DIR="${HOME_SPACE}/build"
INSTALL_DIR="${HOME_SPACE}/install"

[ ! -d "${SOURCE_DIR}" ]  || rm -rf "${SOURCE_DIR}"; mkdir -p "${SOURCE_DIR}"
[ ! -d "${BUILD_DIR}" ]   || rm -rf "${BUILD_DIR}";  mkdir -p "${BUILD_DIR}"
[ ! -d "${INSTALL_DIR}" ] || rm -rf "${INSTALL_DIR}";mkdir -p "${INSTALL_DIR}"