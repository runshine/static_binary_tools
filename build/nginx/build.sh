#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt update && apt-get -y install curl wget unzip

VERSION="v1.28"
#mv ../ttyd-linux-aarch64.tar.gz "$INSTALL_DIR/ttyd-v1.7.7-linux-aarch64.tar.gz
aarch64_linux_data="/build/nginx-linux-aarch64"
x86_64_linux_data="/build/nginx-linux-x86_64"
armhf_linux_data="/build/nginx-linux-armhf"
armel_linux_data="/build/nginx-linux-armel"


process_nginx_data(){
  source_data="$1"
  target_data="$2"
  source_dir="$(dirname "${source_data}")"
  echo "start process nginx file: ${source_data}"
  cd "${BUILD_DIR}"
  mkdir bin
  mkdir conf
  cp ${source_data} bin/nginx
  tar -czvf "$target_data" .
  rm * -rf
}

process_nginx_data "$aarch64_linux_data" "${INSTALL_DIR}/nginx-${VERSION}-linux-aarch64.tar.gz"
process_nginx_data "$x86_64_linux_data" "${INSTALL_DIR}/nginx-${VERSION}-linux-x86_64.tar.gz"
process_nginx_data "$armhf_linux_data" "${INSTALL_DIR}/nginx-${VERSION}-linux-armhf.tar.gz"
process_nginx_data "$armel_linux_data" "${INSTALL_DIR}/nginx-${VERSION}-linux-armel.tar.gz"

echo "done"