#!/usr/bin/env bash
# Install the Rust toolchains and bpf-linker that PROVE needs. Run as the normal user inside the
# VM (or any Debian 13 system with the packages from vm/build.sh's cloud-init seed). Idempotent.
#
#   vm/ssh.sh 'cd ~/prove && scripts/setup-vm.sh'
#
# Versions are the ones the recorded results were built with (docs/ENVIRONMENT.md):
#   stable  1.100.0             userspace, from rust-toolchain.toml
#   nightly nightly-2026-11-13  BPF target, from provd/build.rs (rustc 1.102.0-nightly 8eb778d04)
#   bpf-linker 0.13.0
set -euo pipefail

STABLE=1.100.0
NIGHTLY=nightly-2026-11-13
BPF_LINKER=0.13.0

if ! command -v rustup >/dev/null && [[ ! -x ~/.cargo/bin/rustup ]]; then
    echo ">> installing rustup"
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
fi
# shellcheck disable=SC1090
. ~/.cargo/env

echo ">> toolchains"
rustup toolchain install "$STABLE" --profile minimal --component clippy,rustfmt
rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src

if [[ "$(bpf-linker --version 2>/dev/null)" != "bpf-linker $BPF_LINKER" ]]; then
    echo ">> installing bpf-linker $BPF_LINKER"
    # Prebuilt binary through cargo-binstall; building it from source needs a matching LLVM.
    if ! cargo binstall -V >/dev/null 2>&1; then
        curl -sSfL https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
    fi
    cargo binstall -y --force "bpf-linker@$BPF_LINKER"
fi

echo ">> installed"
rustc "+$STABLE" -V
rustc "+$NIGHTLY" -V
bpf-linker --version
