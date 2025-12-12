#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt-get -y install build-essential ca-certificates wget

mkdir /home/source /home/openvpn
cd /home/source

wget https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz
tar xvzf lzo-2.10.tar.gz
cd lzo-2.10
./configure --prefix=/home/openvpn --enable-static
make && make install

cd /home/source
wget https://github.com/lz4/lz4/archive/v1.9.2.tar.gz
tar xvzf v1.9.2.tar.gz
cd lz4-1.9.2
make && PREFIX=/home/openvpn make install

cd /home/source
wget https://www.openssl.org/source/openssl-1.1.1h.tar.gz
tar xvzf openssl-1.1.1h.tar.gz
cd openssl-1.1.1h
./Configure gcc -static -no-shared --prefix=/home/openvpn
make && make install

cd /home/source
wget https://swupdate.openvpn.org/community/releases/openvpn-2.4.9.tar.gz
tar xvzf openvpn-2.4.9.tar.gz
cd openvpn-2.4.9
./configure --prefix=/home/openvpn --enable-static --disable-shared --disable-debug --disable-plugins OPENSSL_CFLAGS="-I/home/openvpn/include" OPENSSL_LIBS="-L/home/openvpn/lib -lssl -lcrypto" LZO_CFLAGS="-I/home/openvpn/include" LZO_LIBS="-L/home/openvpn/lib -llzo2" LZ4_CFLAGS="-I/home/openvpn/include" LZ4_LIBS="-L/home/openvpn/lib -llz4" IFCONFIG=/sbin/ifconfig ROUTE=/sbin/route NETSTAT=/bin/netstat IPROUTE=/sbin/ip --enable-iproute2
make LIBS="-all-static" && make install

cd /home/openvpn/sbin/
mkdir -p "${INSTALL_DIR}/bin"
cp openvpn ${INSTALL_DIR}/bin/openvpn

strip_elf_files "$INSTALL_DIR/sbin"
strip_elf_files "$INSTALL_DIR/bin"
package_release_tar "${INSTALL_DIR}" openvpn-linux-${ARCH}.tar.gz