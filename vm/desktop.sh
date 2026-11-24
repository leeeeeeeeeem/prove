#!/usr/bin/env bash
# Install a minimal GNOME desktop (Wayland + Xorg) in the running VM, with GDM autologin.
# Used for SPEC M0 item 12 and the S5 agent demo. Boot afterwards with: vm/run.sh --gui
# Snapshot the disk first: qemu-img snapshot -c headless-m4 vm/images/prove.qcow2
set -euo pipefail
source "$(dirname "$0")/config.sh"
ssh "${SSH_OPTS[@]}" "$VM_USER@127.0.0.1" sudo bash -s <<EOF
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends gnome-core gdm3 xserver-xorg xserver-xorg-video-fbdev gnome-session-xsession xdotool wtype
mkdir -p /etc/gdm3
cat > /etc/gdm3/daemon.conf <<CONF
[daemon]
AutomaticLoginEnable=true
AutomaticLogin=$VM_USER
CONF
systemctl set-default graphical.target
EOF
echo "desktop installed; restart with vm/stop.sh && vm/run.sh --gui"
