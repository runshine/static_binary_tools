#!/bin/bash
# build-all.sh

set -e

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

export TZ="GMT+8"
ARCHS=("x86_64" "aarch64" "armhf" "armel" "riscv64")
BUILD_VERSION=$(date +"%Y%m%d.%H%M%S")
VERSION="${BUILD_VERSION}"

sed -i "s/20060107.210405/${VERSION}/g" main.go

go mod tidy
go mod download
go list -m all | grep -v 'golang.org/x' | grep -v 'github.com/google'

echo "开始编译 Sothothv2 Agent $VERSION"

for arch in "${ARCHS[@]}"; do
    echo "编译 $arch 架构..."

    case $arch in
        x86_64)
            GOARCH="amd64"
            GOARM=""
            ;;
        aarch64)
            GOARCH="arm64"
            GOARM=""
            ;;
        armhf)
            GOARCH="arm"
            GOARM="7"
            ;;
        armel)
            GOARCH="arm"
            GOARM="5"
            ;;
        riscv64)
            GOARCH="riscv64"
            GOARM=""
            ;;
        i386)
            GOARCH="386"
            GOARM=""
            ;;
    esac

    if [ -n "$GOARM" ]; then
        CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH GOARM=$GOARM \
        go build -ldflags="-s -w -X main.Version=$VERSION" \
        -o "bin/sothothv2_agent" main.go
        strip_elf_files "./bin/"
        tar -czvf "${INSTALL_DIR}/sothothv2_agent-${VERSION}-linux-${arch}.tar.gz" ./bin/
        rm "bin/sothothv2_agent"
    else
        CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH \
        go build -ldflags="-s -w -X main.Version=$VERSION" \
        -o "bin/sothothv2_agent" main.go
        strip_elf_files "./bin/"
        tar -czvf "${INSTALL_DIR}/sothothv2_agent-${VERSION}-linux-${arch}.tar.gz" ./bin/
        rm "bin/sothothv2_agent"
    fi

    if [ $? -eq 0 ]; then
        echo "  ✓ $arch 编译成功"
    else
        echo "  ✗ $arch 编译失败"
    fi
done

echo "编译完成！"
echo "文件列表："
ls -lh ${INSTALL_DIR}/