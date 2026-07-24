#!/bin/bash

set -eo pipefail

source "$(cd "$(dirname "$0")";pwd)/../common/prepare_dir.sh"
source "$(cd "$(dirname "$0")";pwd)/../common/utils_func.sh"

VERSION="${WSTUNNEL_VERSION:-10.6.2}"
RUST_TARGET="${RUST_TARGET:?RUST_TARGET is required}"
OUTPUT_ARCH="${OUTPUT_ARCH:?OUTPUT_ARCH is required}"
FEATURES="${WSTUNNEL_FEATURES:-ring}"
ZIG_VERSION="${ZIG_VERSION:-0.14.1}"
ZIG_DOWNLOAD_URL="${ZIG_DOWNLOAD_URL:-https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz}"
CARGO_ZIGBUILD_VERSION="${CARGO_ZIGBUILD_VERSION:-0.20.1}"
SOURCE_TAR="v${VERSION}.tar.gz"
SOURCE_URL="https://github.com/erebe/wstunnel/archive/refs/tags/${SOURCE_TAR}"
SOURCE_ROOT="${BUILD_DIR}/wstunnel-${VERSION}"
ZIG_ROOT="${HOME_SPACE}/zig-${ZIG_VERSION}"
ZIG_BIN="${ZIG_ROOT}/zig"

apt-get update
apt-get install -y curl ca-certificates git xz-utils build-essential pkg-config file perl cmake

for cargo_bin_dir in /usr/local/cargo/bin "${HOME}/.cargo/bin"; do
  if [ -d "${cargo_bin_dir}" ]; then
    export PATH="${cargo_bin_dir}:${PATH}"
  fi
done

if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

if ! rustup toolchain list | grep -q '^stable'; then
  rustup toolchain install stable --profile minimal
fi
rustup default stable
if ! rustup target list --installed | grep -qx "${RUST_TARGET}"; then
  rustup target add "${RUST_TARGET}"
fi

if [ ! -x "${ZIG_BIN}" ]; then
  curl -L -o "${SOURCE_DIR}/zig-${ZIG_VERSION}.tar.xz" "${ZIG_DOWNLOAD_URL}"
  mkdir -p "${ZIG_ROOT}"
  tar -xJf "${SOURCE_DIR}/zig-${ZIG_VERSION}.tar.xz" -C "${BUILD_DIR}"
  rm -rf "${ZIG_ROOT}"
  mv "${BUILD_DIR}/zig-x86_64-linux-${ZIG_VERSION}" "${ZIG_ROOT}"
fi
export PATH="${ZIG_ROOT}:${PATH}"

if ! command -v cargo-zigbuild >/dev/null 2>&1; then
  cargo install cargo-zigbuild --locked --version "${CARGO_ZIGBUILD_VERSION}"
fi

curl -L -o "${SOURCE_DIR}/${SOURCE_TAR}" "${SOURCE_URL}"
rm -rf "${SOURCE_ROOT}"
cd "${BUILD_DIR}" && tar -xf "${SOURCE_DIR}/${SOURCE_TAR}"
rm -f "${SOURCE_DIR}/${SOURCE_TAR}"

cd "${SOURCE_ROOT}"

export PKG_CONFIG_ALLOW_CROSS=1
export RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static"

cargo zigbuild \
  --release \
  --locked \
  --package wstunnel-cli \
  --target "${RUST_TARGET}" \
  --no-default-features \
  --features "${FEATURES}"

mkdir -p "${INSTALL_DIR}/bin"
cp "target/${RUST_TARGET}/release/wstunnel" "${INSTALL_DIR}/bin/wstunnel"

strip_elf_files "${INSTALL_DIR}/bin"

if file "${INSTALL_DIR}/bin/wstunnel" | grep -q 'dynamically linked'; then
  echo "wstunnel is dynamically linked, expected a static binary"
  exit 1
fi
if readelf -l "${INSTALL_DIR}/bin/wstunnel" | grep -q 'Requesting program interpreter'; then
  echo "wstunnel contains a PT_INTERP entry, expected a static binary"
  exit 1
fi
if readelf -d "${INSTALL_DIR}/bin/wstunnel" 2>/dev/null | grep -q 'NEEDED'; then
  echo "wstunnel still has shared-library dependencies"
  exit 1
fi

package_release_tar "${INSTALL_DIR}" "wstunnel-v${VERSION}-linux-${OUTPUT_ARCH}.tar.gz"
