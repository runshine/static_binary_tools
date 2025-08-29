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

apt-get -qq -y install build-essential gcc-arm-linux-gnueabi ca-certificates

mkdir /home/source /home/openvpn
cd /home/source

wget https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz
tar xvzf lzo-2.10.tar.gz
cd lzo-2.10
./configure --prefix=/home/openvpn --enable-static --target=arm-linux-gnueabi --host=arm-linux-gnueabi
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
./Configure gcc -static -no-shared --prefix=/home/openvpn --cross-compile-prefix=arm-linux-gnueabi-
make && make install

cd /home/source
wget https://swupdate.openvpn.org/community/releases/openvpn-2.4.9.tar.gz
tar xvzf openvpn-2.4.9.tar.gz
cd openvpn-2.4.9
./configure --target=arm-linux-gnueabi --host=arm-linux-gnueabi --prefix=/home/openvpn --enable-static --disable-shared --disable-debug --disable-plugins OPENSSL_CFLAGS="-I/home/openvpn/include" OPENSSL_LIBS="-L/home/openvpn/lib -lssl -lcrypto" LZO_CFLAGS="-I/home/openvpn/include" LZO_LIBS="-L/home/openvpn/lib -llzo2" LZ4_CFLAGS="-I/home/openvpn/include" LZ4_LIBS="-L/home/openvpn/lib -llz4" IFCONFIG=/sbin/ifconfig ROUTE=/sbin/route NETSTAT=/bin/netstat IPROUTE=/sbin/ip --enable-iproute2
make LIBS="-all-static" && make install

cd /home/openvpn/sbin/
mkdir -p "${INSTALL_DIR}/bin"
cp openvpn ${INSTALL_DIR}/bin/openvpn-linux-$(uname -m)