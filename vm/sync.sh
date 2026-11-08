#!/usr/bin/env bash
# Copy the working tree into the VM at ~/prove (build artifacts stay in the VM).
source "$(dirname "$0")/config.sh"
exec rsync -az --delete --exclude target --exclude vm/images --exclude vm/run --exclude .git --exclude results \
    -e "ssh ${SSH_OPTS[*]}" "$VM_DIR/../" "$VM_USER@127.0.0.1:prove/"
