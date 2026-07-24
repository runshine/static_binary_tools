# static_binary_tools
static_binary_tools build


https://github.com/util-linux/util-linux
hexdump

## wstunnel

Source:
https://github.com/erebe/wstunnel

Build entrypoints:
- `build/wstunnel/build.sh`
- `.github/workflows/build_wstunnel.yml`

Build mode:
- build from source in GitHub Actions
- release binary is required to be fully static
- the build script rejects binaries that still contain `PT_INTERP` or `NEEDED`

Architectures:
- `x86_64` -> `x86_64-unknown-linux-musl`
- `aarch64` -> `aarch64-unknown-linux-musl`
- `armhf` -> `armv7-unknown-linux-musleabihf`
- `armel` -> `armv5te-unknown-linux-musleabi`
- `riscv64` -> `riscv64gc-unknown-linux-musl`

Toolchain notes:
- `x86_64` / `aarch64` / `armhf` / `riscv64` use `zig` + `cargo-zigbuild`
- `armel` uses a separate `musl-cross` toolchain because the shared `zig` musl path was not reliable for `armv5te`
- TLS backend uses upstream default `aws-lc-rs`; `ring` was not kept for `armel`

Validation:
- latest verified successful workflow run: `30080903548`
- all 5 released `wstunnel` binaries were re-checked after download and are statically linked
