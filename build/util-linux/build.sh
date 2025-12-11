#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"

apt-get -y install curl ca-certificates wget xz-utils libsqlite3-dev libncurses-dev libreadline-dev pkgconf file

curl -o "${SOURCE_DIR}/util-linux-2.41.2.tar.gz" https://www.kernel.org/pub/linux/utils/util-linux/v2.41/util-linux-2.41.2.tar.xz
cd "${BUILD_DIR}" && tar -xf "${SOURCE_DIR}/util-linux-2.41.2.tar.gz"
cd "${BUILD_DIR}/util-linux-2.41.2"
mkdir build-static && cd build-static
../configure --prefix=${INSTALL_DIR} --disable-shared --enable-static --disable-libmount --disable-lslogins
sed -i 's/-fsigned-char/--static -lm -lncurses -fsigned-char/g' Makefile
sed -i 's/^READLINE_LIBS = -lreadline$/READLINE_LIBS = -lreadline -ltinfo/' Makefile
sed -i 's/-lsqlite3/-lsqlite3 -lm/g' Makefile
make -j 8
make install


# 函数：strip ELF 文件
strip_elf_files() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        echo "警告: 目录 $dir 不存在，跳过"
        return
    fi
    echo "正在处理目录: $dir"
    # 查找并处理所有普通文件（排除目录、符号链接等）
    find "$dir" -type f -executable -print0 | while IFS= read -r -d '' file; do
        # 使用 file 命令检查是否为 ELF 文件
        if file "$file" | grep -q "ELF.*executable\|ELF.*shared object"; then
            echo "正在 strip: $file"
            # 备份原始文件（可选）
            # cp "$file" "$file.backup"
            # 执行 strip
            if strip --strip-all "$file" 2>/dev/null; then
                echo "  ✓ 成功"
            else
                echo "  ✗ 失败: $file 可能不是有效的 ELF 文件或已经 stripped"
            fi
        fi
    done
}

# 主程序
echo "开始处理 ELF 文件 strip 操作"
echo "================================"
# 处理 bin 目录
if [[ -d "$INSTALL_DIR/bin" ]]; then
    strip_elf_files "$INSTALL_DIR/bin"
else
    echo "警告: $INSTALL_DIR/bin 目录不存在，跳过"
fi

# 处理 sbin 目录
if [[ -d "$INSTALL_DIR/sbin" ]]; then
    strip_elf_files "$INSTALL_DIR/sbin"
else
    echo "警告: $INSTALL_DIR/sbin 目录不存在，跳过"
fi


cd "${INSTALL_DIR}" &&tar -czvf ../util-linux-linux-$(uname -m).tar.gz" *

