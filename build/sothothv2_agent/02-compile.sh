#!/bin/bash
# build-all.sh

set -e

ARCHS=("x86_64" "aarch64" "armhf" "armel" "riscv64")
VERSION="v1.0.0"

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
        tar -czvf "${INSTALL_DIR}/sothothv2_agent-${VERSION}-linux-${arch}" ./bin/
        rm "bin/sothothv2_agent"
    else
        CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH \
        go build -ldflags="-s -w -X main.Version=$VERSION" \
        -o "bin/sothothv2_agent" main.go
        tar -czvf "${INSTALL_DIR}/sothothv2_agent-${VERSION}-linux-${arch}" ./bin/
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