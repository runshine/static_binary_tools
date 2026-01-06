#!/bin/bash

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
            if strip -s "$file" 2>/dev/null; then
                echo "  ✓ 成功"
            else
                echo "  ✗ 失败: $file 可能不是有效的 ELF 文件或已经 stripped"
            fi
        fi
    done
}

package_release_tar(){
  local dir="$1"
  local target_release_tar="$2"
  if [[ ! -d "$dir" ]]; then
      echo "警告: 目录 $dir 不存在，跳过"
      return
  fi
  cd "$dir"
  tar -czvf ../$target_release_tar .
  rm * -rf
  mv ../$target_release_tar .
}