#!/bin/bash

set -e

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt update && apt-get -y install curl wget unzip
_VERSION="29.1.3"

ARCH_LIST=("armel" "armhf" "aarch64" "x86_64")

# shellcheck disable=SC2068
for ARCH in ${ARCH_LIST[@]};
do
  if [ "$ARCH" = "armel" ];then
    VERSION="29.1.0"
  else
    VERSION="${_VERSION}"
  fi
  echo "Process docker: $VERSION , ARCH: $ARCH"
  if [ "$ARCH" = "armhf" ];then
    DOCKER_URL="https://download.docker.com/linux/static/stable/${ARCH}/docker-${VERSION}.tgz"
    DOCKER_COMPOSE_URL="https://github.com/docker/compose/releases/download/v5.0.1/docker-compose-linux-armv7"
  elif [ "$ARCH" = "armel" ];then
    DOCKER_URL="/build/docker-linux-armel.tar.gz"
    DOCKER_COMPOSE_URL="/build/docker-compose-linux-armel"
  else
    DOCKER_URL="https://download.docker.com/linux/static/stable/${ARCH}/docker-${VERSION}.tgz"
    DOCKER_COMPOSE_URL="https://github.com/docker/compose/releases/download/v5.0.1/docker-compose-linux-${ARCH}"
  fi

  if [ ! -f "${DOCKER_URL}" ];then
    [ ! -f "$BUILD_DIR/docker-${VERSION}.tgz" ] || rm -rf "$BUILD_DIR/docker-${VERSION}.tgz"
    curl -L -o "$BUILD_DIR/docker-${VERSION}.tgz" "${DOCKER_URL}"
  else
    cp "${DOCKER_URL}" "$BUILD_DIR/docker-${VERSION}.tgz"
  fi

  if [ ! -f "${DOCKER_COMPOSE_URL}" ];then
    [ ! -f "$BUILD_DIR/docker-compose" ] || rm -rf "$BUILD_DIR/docker-compose"
    curl -L -o "$BUILD_DIR/docker-compose" "${DOCKER_COMPOSE_URL}"
  else
    cp "${DOCKER_COMPOSE_URL}" "$BUILD_DIR/docker-compose"
  fi

  cd "$BUILD_DIR"
  tar -zxvf docker-${VERSION}.tgz
  mv docker-compose docker/docker-compose
  mv docker bin
  rm -rf docker-${VERSION}.tgz
  mkdir conf
  cp /build/config.toml         conf/config.toml
  cp /build/daemon.json         conf/daemon.json
  cp /build/docker-swarm.conf   conf/docker-swarm.conf
  tar -czvf ../docker-${VERSION}-linux-${ARCH}.tar.gz .
  mv  ../docker-${VERSION}-linux-${ARCH}.tar.gz "$INSTALL_DIR/docker-${VERSION}-linux-${ARCH}.tar.gz"
  cd "$BUILD_DIR"
  rm * -rf
done

echo "done"
