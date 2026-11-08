#!/usr/bin/env bash
# Fetch the Debian 13 arm64 cloud image and create the PROVE VM disk + cloud-init seed.
# Usage: vm/build.sh [--force]
set -euo pipefail
source "$(dirname "$0")/config.sh"
mkdir -p "$IMG_DIR" "$RUN_DIR"

if [[ ! -f "$IMG_DIR/$BASE_IMG" ]]; then
    echo ">> downloading $BASE_IMG"
    curl -L --fail -o "$IMG_DIR/$BASE_IMG.part" "$BASE_URL/$BASE_IMG"
    want="$(curl -sL --fail "$BASE_URL/SHA512SUMS" | awk -v f="$BASE_IMG" '$2==f{print $1}')"
    got="$(shasum -a 512 "$IMG_DIR/$BASE_IMG.part" | awk '{print $1}')"
    [[ -n "$want" && "$want" == "$got" ]] || { echo "checksum mismatch" >&2; exit 1; }
    mv "$IMG_DIR/$BASE_IMG.part" "$IMG_DIR/$BASE_IMG"
    echo "$got  $BASE_IMG" > "$IMG_DIR/$BASE_IMG.sha512"
fi

if [[ -f "$DISK" && "${1:-}" != "--force" ]]; then
    echo ">> $DISK exists (use --force to recreate)"
else
    echo ">> creating $DISK"
    rm -f "$DISK"
    qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMG" "$DISK" "$DISK_SIZE"
    dd if=/dev/zero of="$VARS" bs=1048576 count=64 status=none
fi

echo ">> building cloud-init seed"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
pub="$(cat "$SSH_KEY.pub")"
cat > "$tmp/meta-data" <<META
instance-id: prove-vm-1
local-hostname: prove
META
cat > "$tmp/user-data" <<USER
#cloud-config
users:
  - name: $VM_USER
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - $pub
ssh_pwauth: false
package_update: true
packages: [rsync, build-essential, pkg-config, curl, git, bpftool, clang, llvm, libelf-dev, python3-evdev, evtest, strace, bpftrace, linux-headers-arm64]
runcmd:
  - [touch, /var/lib/cloud/prove-seed-done]
USER
rm -f "$SEED"
if command -v hdiutil >/dev/null; then
    hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata -o "$SEED" "$tmp"
else
    genisoimage -quiet -output "$SEED" -volid cidata -joliet -rock "$tmp/user-data" "$tmp/meta-data"
fi
echo ">> done. Start with vm/run.sh"
