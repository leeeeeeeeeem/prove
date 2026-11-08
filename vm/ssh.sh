#!/usr/bin/env bash
# Run a command in the VM (or open a shell). Usage: vm/ssh.sh [command...]
source "$(dirname "$0")/config.sh"
exec ssh "${SSH_OPTS[@]}" "$VM_USER@127.0.0.1" "$@"
