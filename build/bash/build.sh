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

apt install -y git gnupg curl autoconf

#cd /data && ./build.sh linux ${{matrix.arch}} && mv -v releases/bash releases/bash-linux-${{matrix.arch}}
bash_version="5.2"
bash_patch_level=37
musl_version="1.2.5"
CFLAGS="-Wno-error=implicit-function-declaration"

export bash_version
export bash_patch_level
export musl_version
export CFLAGS


set -euo pipefail
shopt -s nullglob

# Silence these
pushd() { command pushd "$@" >/dev/null; }

popd() { command popd >/dev/null; }

# Only pull files that don't already exist
mycurl() {
  (($# == 2)) || return
  [[ -f ${1##*/} ]] || { echo "File: ${1##*/} | Url: ${1}" && curl -sLO "$1"; }
  [[ -f ${1##*/}.${2} || ${NO_SIGS:-} ]] || {
    echo "File: ${1##*/}.${2} | Url: ${1}.${2}" && curl -sLO "${1}.${2}"
    gpg --trust-model always --verify "${1##*/}.${2}" "${1##*/}" 2>/dev/null
  }
}

main() {
  [[ ${1:-} ]] || { echo "! no target specified" >&2 && exit 1; }
  [[ ${2:-} ]] || { echo "! no arch specified" >&2 && exit 1; }

  declare -r target=${1} arch=${2} tag=${3:-}
  declare -r bash_mirror='https://ftp.gnu.org/gnu/bash'
  declare -r musl_mirror='https://musl.libc.org/releases'

  # Ensure we are in the project root
  pushd "${0%/*}"
  # load version info
  # shellcheck source=version.sh
  #. "./version${tag:+-$tag}.sh"

  # make build directory
  mkdir -p build && pushd build

  # pre-prepare gpg for verificaiton
  echo "= preparing gpg"
  export GNUPGHOME=${PWD}/.gnupg
  # public key for bash
  gpg --quiet --list-keys 7C0135FB088AAF6C66C650B9BB5869F064EA74AB ||
    gpg --quiet --keyserver hkps://keyserver.ubuntu.com:443 \
      --recv-keys 7C0135FB088AAF6C66C650B9BB5869F064EA74AB
  # public key for musl
  gpg --quiet --list-keys 836489290BB6B70F99FFDA0556BCDB593020450F ||
    gpg --quiet --keyserver hkps://keyserver.ubuntu.com:443 \
      --recv-keys 836489290BB6B70F99FFDA0556BCDB593020450F

  # download tarballs
  echo "= downloading bash ${bash_version}"
  mycurl ${bash_mirror}/bash-${bash_version}.tar.gz sig

  echo "= extracting bash ${bash_version}"
  rm -fr bash-${bash_version}
  tar -xf "bash-${bash_version}.tar.gz"

  echo "= patching bash ${bash_version} | patches: ${bash_patch_level}"
  for ((lvl = 1; lvl <= bash_patch_level; lvl++)); do
    printf -v bash_patch 'bash%s-%03d' "${bash_version/\./}" "${lvl}"
    mycurl "${bash_mirror}/bash-${bash_version}-patches/${bash_patch}" sig
    pushd bash-${bash_version} && patch -sp0 <../"${bash_patch}" && popd
  done

  echo "= patching with any custom patches we have"
  for patch in ../custom/bash"${bash_version/\./}"*.patch; do
    echo "Applying ${patch}"
    pushd bash-${bash_version} && patch -sp1 <../"${patch}" && popd
  done

  configure_args=(--enable-silent-rules)

  if [[ $target == linux ]]; then
    if . /etc/os-release && [[ $ID == alpine ]]; then
      echo "= skipping installation of musl (already installed on Alpine)"
    else
      install_dir=${PWD}/musl-install-${musl_version}
      if [[ -f ${install_dir}/bin/musl-gcc ]]; then
        echo "= reusing existing musl ${musl_version}"
      else
        echo "= downloading musl ${musl_version}"
        mycurl ${musl_mirror}/musl-${musl_version}.tar.gz asc

        echo "= extracting musl ${musl_version}"
        rm -fr musl-${musl_version}
        tar -xf musl-${musl_version}.tar.gz

        echo "= building musl ${musl_version}"
        pushd musl-${musl_version}
        ./configure --prefix="${install_dir}" "${configure_args[@]}"
        make -s install
        popd # musl-${musl-version}
        rm -fr musl-${musl_version}
      fi

      echo "= setting CC to musl-gcc ${musl_version}"
      export CC=${install_dir}/bin/musl-gcc
    fi
    export CFLAGS="${CFLAGS:-} -Os -static"
  else
    echo "= WARNING: your platform does not support static binaries."
    echo "= (This is mainly due to non-static libc availability.)"
    if [[ $target == macos ]]; then
      # set minimum version of macOS to 10.13
      export MACOSX_DEPLOYMENT_TARGET="10.13"
      export CC="clang -std=c89 -Wno-return-type"

      # use included gettext to avoid reading from other places, like homebrew
      configure_args=("${configure_args[@]}" "--with-included-gettext")

      # if $arch is aarch64 for mac, target arm64e
      if [[ $arch == aarch64 ]]; then
        export CFLAGS="${CFLAGS:-} -Os -target arm64-apple-macos"
        configure_args=("${configure_args[@]}" "--host=aarch64-apple-darwin")
      else
        export CFLAGS="${CFLAGS:-} -Os -target x86_64-apple-macos10.12"
        configure_args=("${configure_args[@]}" "--host=x86_64-apple-macos10.12")
      fi
    fi
  fi

  echo "= building bash ${bash_version}"
  pushd bash-${bash_version}
  export CPPFLAGS="${CFLAGS}" # Some versions need both set
  autoconf -f && ./configure --without-bash-malloc "${configure_args[@]}"
  make -s
  popd # bash-${bash_version}
  popd # build

  echo "= extracting bash ${bash_version} binary"
  mkdir -p releases
  cp build/bash-${bash_version}/bash releases/bash-${bash_version}-static
  strip -s releases/bash-${bash_version}-static
  rm -fr build/bash-${bash_version}
  echo "= done"
}

# Only execute if not being sourced
[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0 && main linux $(uname -m)

mkdir -p /build/install/bin && mv -v releases/bash-${bash_version}-static /build/install/bin/bash-linux-$(uname -m)