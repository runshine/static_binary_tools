#!/bin/bash
# 适用于 Ubuntu x86_64 的 Go 语言自动安装脚本
# 功能：下载最新稳定版、自动安装、配置环境变量、验证
# 全程无需人工干预

set -e # 遇到任何错误则退出脚本

echo "=== 开始自动安装 Go 语言环境 (x86_64) ==="

# 1. 下载最新稳定版 Go
echo "正在获取最新稳定版 Go 的下载链接..."
DOWNLOAD_URL="https://go.dev/dl/"
# 从官网下载页面解析最新的稳定版 .tar.gz 文件链接 (适用于Linux amd64)
LATEST_TAR=$(curl -s https://go.dev/dl/ | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?\.linux-amd64\.tar\.gz' | head -1)
if [[ -z "$LATEST_TAR" ]]; then
    # 如果解析失败，使用一个已知的最新版本作为后备（请定期更新此版本号）
    echo "警告：无法从官网解析最新版本，使用已知稳定版本。"
    LATEST_TAR="go1.24.1.linux-amd64.tar.gz" # 示例版本，可替换[citation:1]
fi

FULL_URL="https://dl.google.com/go/${LATEST_TAR}"
echo "将下载: ${LATEST_TAR}"

# 清理可能的旧安装和临时文件
echo "清理旧版本和临时文件..."
sudo rm -rf /usr/local/go 2>/dev/null || true
rm -f /tmp/${LATEST_TAR} 2>/dev/null || true

# 下载安装包到临时目录
echo "正在下载安装包..."
cd /tmp
if ! wget -q --show-progress "${FULL_URL}"; then
    echo "错误：下载失败，请检查网络连接或URL。"
    exit 1
fi

# 2. 安装到系统目录
echo "正在解压安装到 /usr/local..."
sudo tar -C /usr/local -xzf ${LATEST_TAR}
if [ $? -ne 0 ]; then
    echo "错误：解压安装失败。"
    exit 1
fi

# 3. 配置当前用户的环境变量 (PATH)
echo "配置环境变量..."
# 获取用户当前的shell配置文件
SHELL_RC="${HOME}/.bashrc"
# 确保将Go的bin目录添加到PATH中
if ! grep -q '/usr/local/go/bin' "${SHELL_RC}"; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> "${SHELL_RC}"
    echo "已将 /usr/local/go/bin 添加到 ${SHELL_RC}"
fi

# 立即生效（对当前shell会话）[citation:7]
export PATH=$PATH:/usr/local/go/bin

# 4. 验证安装
echo "验证安装..."
if command -v go >/dev/null 2>&1; then
    GO_VERSION=$(go version)
    echo "✅ Go 安装成功：${GO_VERSION}"
    echo "✅ 已安装到：/usr/local/go"
    echo "✅ 环境变量 PATH 已更新。请重新打开终端或运行 'source ~/.bashrc' 使配置对所有新会话生效。"

    # 可选：运行一个简单的编译测试
    echo "---"
    echo "正在执行快速编译测试..."
    TEST_DIR=$(mktemp -d)
    cd "${TEST_DIR}"
    cat > hello.go << 'EOF'
package main
import "fmt"
func main() {
    fmt.Println("✅ Go 环境测试成功！可以开始编译你的代码了。")
}
EOF
    go run hello.go
    rm -rf "${TEST_DIR}"
else
    echo "❌ 安装验证失败：无法找到 'go' 命令。"
    exit 1
fi

echo "=== 安装完成 ==="
echo "你现在可以在终端中使用 'go build'、'go run' 等命令来编译你的monitor程序了。"