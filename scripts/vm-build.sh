#!/usr/bin/env bash
# Sync the tree into the VM and build there. Usage: scripts/vm-build.sh [cargo args...]
# Prints only errors and the final lines unless V=1.
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
"$root/vm/sync.sh" || exit 1
if [[ "${V:-0}" == 1 ]]; then filter=(cat); else filter=(grep -v -E '^\s*(Compiling|Downloaded|Downloading|Checking|Locking|Adding|Updating) '); fi
"$root/vm/ssh.sh" ". ~/.cargo/env; cd prove && cargo build ${*:-} 2>&1 | sed -e 's/^  cargo::warning=//'" | "${filter[@]}"
