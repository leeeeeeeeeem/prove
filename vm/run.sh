#!/usr/bin/env bash
# Boot the PROVE VM in the background.
# Usage: vm/run.sh [--gui]     (--gui adds a virtio-gpu and a VNC display on :5 for the desktop milestones)
#
# Input devices exposed as "physical" hardware (SPEC section 4, see docs/DEVIATIONS.md for the
# PS/2 substitution on arm64): usb-kbd, usb-tablet, virtio-keyboard-pci, and a second usb-kbd on
# its own xHCI controller. The virtio keyboard sits on PCIe port hp0 so it can be unplugged;
# hp1 is an empty port for hot-plug tests
# (e.g. vm/qmp.py plug virtio-keyboard-pci k1 bus=hp1).
set -euo pipefail
source "$(dirname "$0")/config.sh"
mkdir -p "$RUN_DIR"

if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "VM already running (pid $(cat "$PIDFILE"))"; exit 0
fi
rm -f "$QMP_SOCK"

case "$(uname -s)" in
    Darwin) ACCEL=hvf ;;
    *)      ACCEL=kvm ;;
esac

display=(-display none)
if [[ "${1:-}" == "--gui" ]]; then
    display=(-device virtio-gpu-pci -vnc 127.0.0.1:5)
fi

qemu-system-aarch64 \
    -name prove -machine virt -accel "$ACCEL" -cpu host -smp 4 -m 4G \
    -drive if=pflash,format=raw,readonly=on,file="$EFI_CODE" \
    -drive if=pflash,format=raw,file="$VARS" \
    -drive if=none,id=hd0,format=qcow2,discard=unmap,detect-zeroes=unmap,file="$DISK" -device virtio-blk-pci,drive=hd0 \
    -drive if=none,id=seed,format=raw,readonly=on,file="$SEED" -device virtio-blk-pci,drive=seed \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22 -device virtio-net-pci,netdev=n0 \
    -device virtio-rng-pci \
    -device qemu-xhci,id=xhci0 \
    -device usb-kbd,bus=xhci0.0,id=usbkbd0 \
    -device usb-tablet,bus=xhci0.0,id=usbtablet0 \
    -device pcie-root-port,id=hp0,chassis=1 -device pcie-root-port,id=hp1,chassis=2 \
    -device virtio-keyboard-pci,id=viokbd0,bus=hp0 \
    -device qemu-xhci,id=xhci1 \
    -device usb-kbd,bus=xhci1.0,id=usbkbd1 \
    -qmp unix:"$QMP_SOCK",server=on,wait=off \
    -serial file:"$SERIAL_LOG" \
    "${display[@]}" \
    -pidfile "$PIDFILE" -daemonize

echo "VM started (pid $(cat "$PIDFILE")), ssh port $SSH_PORT, QMP $QMP_SOCK"
