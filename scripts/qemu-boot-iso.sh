#!/bin/bash
# Boot quickfw.iso in QEMU with port-forwarded management.
#
# Uses direct kernel+initrd boot to bypass the isolinux menu
# (which has `timeout 0` = indefinite wait) and enable serial console.
#
# Host ports mapped to guest:
#   8443 -> 443  (HTTPS dashboard)
#   8080 -> 3000 (HTTP redirect)
#   2222 -> 22   (SSH)
#
# Usage: bash qemu-boot-iso.sh [path-to-iso]

set -euo pipefail

ISO="${1:-/opt/quickfw-src/output/quickfw.iso}"
LOGDIR=/var/log/quickfw-qemu
PIDFILE=/run/quickfw-qemu.pid
MONITOR=/run/quickfw-qemu.monitor
SERIAL_LOG=$LOGDIR/serial.log
SERIAL_SOCK=/run/quickfw-qemu.serial
KERNEL=/boot/quickfw-iso/vmlinuz
INITRD=/boot/quickfw-iso/initrd.img

mkdir -p "$LOGDIR"

if [[ ! -f "$ISO" ]]; then
    echo "ISO not found at $ISO" >&2
    exit 1
fi

if [[ ! -f "$KERNEL" || ! -f "$INITRD" ]]; then
    echo "Kernel/initrd missing — extracting from ISO..."
    mkdir -p /boot/quickfw-iso /mnt/iso
    mount -o loop,ro "$ISO" /mnt/iso
    cp -f /mnt/iso/live/vmlinuz "$KERNEL"
    cp -f /mnt/iso/live/initrd.img "$INITRD"
    umount /mnt/iso
fi

# Stop any previous instance
if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "[+] Stopping existing QEMU (pid $(cat "$PIDFILE"))"
    kill "$(cat "$PIDFILE")" || true
    sleep 2
fi
rm -f "$PIDFILE" "$MONITOR"

# KVM acceleration if available, else TCG
ACCEL_ARGS="-enable-kvm -cpu host"
if [[ ! -w /dev/kvm ]]; then
    echo "[!] /dev/kvm not writable, falling back to TCG (slower)"
    ACCEL_ARGS=""
fi

# Truncate old serial log
: > "$SERIAL_LOG"

echo "[+] Launching QEMU with ISO: $ISO"
echo "[+]                  kernel:  $KERNEL"
echo "[+]                  initrd:  $INITRD"
echo "[+] Serial log: $SERIAL_LOG"

# boot=live components: standard live-boot args
# hostname=quickfw toram: from ISO's live.cfg
# console=ttyS0,115200: route kernel + systemd logs to serial
# quiet: suppress kernel spam (optional)
KERNEL_APPEND="boot=live components hostname=quickfw toram console=ttyS0,115200"

qemu-system-x86_64 \
    $ACCEL_ARGS \
    -smp 2 \
    -m 2048 \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "$KERNEL_APPEND" \
    -cdrom "$ISO" \
    -netdev user,id=net0,hostfwd=tcp::8443-:443,hostfwd=tcp::8080-:3000,hostfwd=tcp::2222-:22 \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    -serial "unix:$SERIAL_SOCK,server=on,wait=off" \
    -monitor "unix:$MONITOR,server,nowait" \
    -pidfile "$PIDFILE" \
    -daemonize

sleep 2
if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "[+] QEMU running as PID $(cat "$PIDFILE")"
else
    echo "[x] QEMU did not start" >&2
    exit 1
fi

echo "[+] Serial socket:      $SERIAL_SOCK"
echo "[+] Serial log (passive): $SERIAL_LOG"
echo "[+] QEMU monitor:       socat - UNIX-CONNECT:$MONITOR"
echo "[+] Dashboard (guest):  https://172.16.60.145:8443/"
echo "[+] SSH to guest:       ssh -p 2222 root@172.16.60.145"
