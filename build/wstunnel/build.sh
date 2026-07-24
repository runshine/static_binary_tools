#!/bin/bash

set -eo pipefail

source "$(cd "$(dirname "$0")";pwd)/../common/prepare_dir.sh"
source "$(cd "$(dirname "$0")";pwd)/../common/utils_func.sh"

VERSION="${WSTUNNEL_VERSION:-10.6.2}"
RUST_TARGET="${RUST_TARGET:?RUST_TARGET is required}"
OUTPUT_ARCH="${OUTPUT_ARCH:?OUTPUT_ARCH is required}"
FEATURES="${WSTUNNEL_FEATURES:-aws-lc-rs}"
ZIG_VERSION="${ZIG_VERSION:-0.14.1}"
ZIG_DOWNLOAD_URL="${ZIG_DOWNLOAD_URL:-https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz}"
CARGO_ZIGBUILD_VERSION="${CARGO_ZIGBUILD_VERSION:-0.20.1}"
MUSL_CROSS_VERSION="${MUSL_CROSS_VERSION:-20260515}"
ARMEL_MUSL_TOOLCHAIN_URL="${ARMEL_MUSL_TOOLCHAIN_URL:-https://github.com/cross-tools/musl-cross/releases/download/${MUSL_CROSS_VERSION}/arm-unknown-linux-musleabi.tar.xz}"
SOURCE_TAR="v${VERSION}.tar.gz"
SOURCE_URL="https://github.com/erebe/wstunnel/archive/refs/tags/${SOURCE_TAR}"
SOURCE_ROOT="${BUILD_DIR}/wstunnel-${VERSION}"
ZIG_ROOT="${HOME_SPACE}/zig-${ZIG_VERSION}"
ZIG_BIN="${ZIG_ROOT}/zig"
ARMEL_TOOLCHAIN_ROOT="${HOME_SPACE}/arm-unknown-linux-musleabi"

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

curl -L -o "${SOURCE_DIR}/${SOURCE_TAR}" "${SOURCE_URL}"
rm -rf "${SOURCE_ROOT}"
cd "${BUILD_DIR}" && tar -xf "${SOURCE_DIR}/${SOURCE_TAR}"
rm -f "${SOURCE_DIR}/${SOURCE_TAR}"

cd "${SOURCE_ROOT}"

export PKG_CONFIG_ALLOW_CROSS=1
export RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static"

if [ "${RUST_TARGET}" = "armv5te-unknown-linux-musleabi" ]; then
  if ! find "${ARMEL_TOOLCHAIN_ROOT}/bin" -maxdepth 1 -type f -name '*-gcc' >/dev/null 2>&1; then
    curl -L -o "${SOURCE_DIR}/arm-unknown-linux-musleabi.tar.xz" "${ARMEL_MUSL_TOOLCHAIN_URL}"
    tar -xJf "${SOURCE_DIR}/arm-unknown-linux-musleabi.tar.xz" -C "${BUILD_DIR}"
    rm -rf "${ARMEL_TOOLCHAIN_ROOT}"
    extracted_dir="$(find "${BUILD_DIR}" -maxdepth 1 -mindepth 1 -type d -name 'arm-unknown-linux-musleabi*' | head -n 1)"
    if [ -z "${extracted_dir}" ]; then
      echo "Unable to locate extracted armel musl toolchain directory"
      exit 1
    fi
    mv "${extracted_dir}" "${ARMEL_TOOLCHAIN_ROOT}"
  fi
  export PATH="${ARMEL_TOOLCHAIN_ROOT}/bin:${PATH}"
  armel_gcc="$(find "${ARMEL_TOOLCHAIN_ROOT}/bin" -maxdepth 1 -type f -name '*-gcc' | head -n 1)"
  armel_ar="$(find "${ARMEL_TOOLCHAIN_ROOT}/bin" -maxdepth 1 -type f -name '*-ar' | head -n 1)"
  if [ -z "${armel_gcc}" ] || [ -z "${armel_ar}" ]; then
    echo "Unable to locate armel musl compiler tools"
    exit 1
  fi
  export CC_armv5te_unknown_linux_musleabi="${armel_gcc}"
  export AR_armv5te_unknown_linux_musleabi="${armel_ar}"
  export CARGO_TARGET_ARMV5TE_UNKNOWN_LINUX_MUSLEABI_LINKER="${armel_gcc}"
  cargo build \
    --release \
    --locked \
    --package wstunnel-cli \
    --target "${RUST_TARGET}" \
    --no-default-features \
    --features "${FEATURES}"
else
  if [ ! -x "${ZIG_BIN}" ]; then
    curl -L -o "${SOURCE_DIR}/zig-${ZIG_VERSION}.tar.xz" "${ZIG_DOWNLOAD_URL}"
    mkdir -p "${ZIG_ROOT}"
    tar -xJf "${SOURCE_DIR}/zig-${ZIG_VERSION}.tar.xz" -C "${BUILD_DIR}"
    rm -rf "${ZIG_ROOT}"
    mv "${BUILD_DIR}/zig-x86_64-linux-${ZIG_VERSION}" "${ZIG_ROOT}"
  fi
  export PATH="${ZIG_ROOT}:${PATH}"

  if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    cargo install cargo-zigbuild --target x86_64-unknown-linux-gnu --locked --version "${CARGO_ZIGBUILD_VERSION}"
  fi

  cargo zigbuild \
    --release \
    --locked \
    --package wstunnel-cli \
    --target "${RUST_TARGET}" \
    --no-default-features \
    --features "${FEATURES}"
fi

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
