#!/usr/bin/env bash
# Wait until the VM accepts SSH and cloud-init has finished. Usage: vm/wait.sh [timeout_s]
source "$(dirname "$0")/config.sh"
deadline=$(( $(date +%s) + ${1:-600} ))
while (( $(date +%s) < deadline )); do
    if ssh "${SSH_OPTS[@]}" "$VM_USER@127.0.0.1" 'cloud-init status --wait >/dev/null 2>&1; test -f /var/lib/cloud/prove-seed-done' 2>/dev/null; then
        echo "VM ready"; exit 0
    fi
    perl -e 'select(undef,undef,undef,3)'
done
echo "timed out waiting for VM" >&2; exit 1
