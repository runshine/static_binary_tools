#!/bin/bash

set -eo pipefail

source "$(cd "$(dirname "$0")";pwd)/../common/prepare_dir.sh"
source "$(cd "$(dirname "$0")";pwd)/../common/utils_func.sh"

VERSION="${WSTUNNEL_VERSION:-10.6.2}"
RUST_TARGET="${RUST_TARGET:?RUST_TARGET is required}"
OUTPUT_ARCH="${OUTPUT_ARCH:?OUTPUT_ARCH is required}"
LINKER="${LINKER:-}"
STRIP_TOOL="${STRIP_TOOL:-}"
FEATURES="${WSTUNNEL_FEATURES:-ring}"
SOURCE_TAR="v${VERSION}.tar.gz"
SOURCE_URL="https://github.com/erebe/wstunnel/archive/refs/tags/${SOURCE_TAR}"
SOURCE_ROOT="${BUILD_DIR}/wstunnel-${VERSION}"

apt-get update
apt-get install -y curl ca-certificates git xz-utils build-essential pkg-config file perl cmake

if [ -n "${APT_EXTRA_PACKAGES:-}" ]; then
  apt-get install -y ${APT_EXTRA_PACKAGES}
fi

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

if [ -n "${LINKER}" ]; then
  target_key="$(echo "${RUST_TARGET}" | tr '[:lower:]-' '[:upper:]_')"
  export "CARGO_TARGET_${target_key}_LINKER=${LINKER}"
  if [ -z "${STRIP_TOOL}" ]; then
    STRIP_TOOL="${LINKER%gcc}strip"
  fi
fi

cargo build \
  --release \
  --locked \
  --package wstunnel-cli \
  --target "${RUST_TARGET}" \
  --no-default-features \
  --features "${FEATURES}"

mkdir -p "${INSTALL_DIR}/bin"
cp "target/${RUST_TARGET}/release/wstunnel" "${INSTALL_DIR}/bin/wstunnel"

if [ -n "${STRIP_TOOL}" ] && command -v "${STRIP_TOOL}" >/dev/null 2>&1; then
  "${STRIP_TOOL}" -s "${INSTALL_DIR}/bin/wstunnel" || true
else
  strip_elf_files "${INSTALL_DIR}/bin"
fi
package_release_tar "${INSTALL_DIR}" "wstunnel-v${VERSION}-linux-${OUTPUT_ARCH}.tar.gz"
