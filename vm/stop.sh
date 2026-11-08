#!/usr/bin/env bash
# Shut the VM down cleanly (falls back to killing QEMU).
source "$(dirname "$0")/config.sh"
[[ -f "$PIDFILE" ]] || { echo "not running"; exit 0; }
pid="$(cat "$PIDFILE")"
ssh "${SSH_OPTS[@]}" "$VM_USER@127.0.0.1" 'sudo poweroff' 2>/dev/null || true
for _ in $(seq 30); do kill -0 "$pid" 2>/dev/null || { rm -f "$PIDFILE"; echo stopped; exit 0; }; perl -e 'select(undef,undef,undef,1)'; done
kill "$pid" 2>/dev/null; rm -f "$PIDFILE"; echo killed
