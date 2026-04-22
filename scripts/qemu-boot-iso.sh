#!/bin/bash
# Boot quickfw.iso in QEMU with 4 virtual NICs:
#   eth0 = SLIRP user-mode net (management + hostfwd)
#   eth1 = WAN   (socket net between appliance & fake ISP — isolated)
#   eth2 = LAN   (socket net — can simulate LAN clients later)
#   eth3 = DMZ   (socket net — reserved)
#
# Host ports mapped to the SLIRP NIC only:
#   8443 -> 443  (HTTPS dashboard)
#   8080 -> 3000 (HTTP redirect)
#   2222 -> 22   (SSH if enabled)
#
# Extracts kernel+initrd from the ISO because the isolinux menu has
# `timeout 0` = infinite wait.

set -euo pipefail

ISO="${1:-/opt/quickfw-src/output/quickfw.iso}"
LOGDIR=/var/log/quickfw-qemu
PIDFILE=/run/quickfw-qemu.pid
MONITOR=/run/quickfw-qemu.monitor
SERIAL_SOCK=/run/quickfw-qemu.serial
SERIAL_LOG=$LOGDIR/serial.log
KERNEL=/boot/quickfw-iso/vmlinuz
INITRD=/boot/quickfw-iso/initrd.img

mkdir -p "$LOGDIR"

if [[ ! -f "$ISO" ]]; then
    echo "ISO not found at $ISO" >&2
    exit 1
fi

if [[ ! -f "$KERNEL" || ! -f "$INITRD" ]]; then
    mkdir -p /boot/quickfw-iso /mnt/iso
    mount -o loop,ro "$ISO" /mnt/iso
    cp -f /mnt/iso/live/vmlinuz "$KERNEL"
    cp -f /mnt/iso/live/initrd.img "$INITRD"
    umount /mnt/iso
fi

# Stop previous instance
if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    kill "$(cat "$PIDFILE")" || true
    sleep 2
fi
rm -f "$PIDFILE" "$MONITOR" "$SERIAL_SOCK"

ACCEL_ARGS="-enable-kvm -cpu host"
[[ ! -w /dev/kvm ]] && ACCEL_ARGS=""

KERNEL_APPEND="boot=live components hostname=quickfw toram console=ttyS0,115200"

: > "$SERIAL_LOG"

echo "[+] Launching QEMU with ISO: $ISO"

qemu-system-x86_64 \
    $ACCEL_ARGS \
    -smp 2 \
    -m 2048 \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "$KERNEL_APPEND" \
    -cdrom "$ISO" \
    \
    -netdev user,id=mgmt,hostfwd=tcp::8443-:443,hostfwd=tcp::8080-:3000,hostfwd=tcp::2222-:22 \
    -device virtio-net-pci,netdev=mgmt,mac=52:54:00:00:00:01 \
    \
    -netdev socket,id=wan,listen=127.0.0.1:11001 \
    -device virtio-net-pci,netdev=wan,mac=52:54:00:00:00:02 \
    \
    -netdev socket,id=lan,listen=127.0.0.1:11002 \
    -device virtio-net-pci,netdev=lan,mac=52:54:00:00:00:03 \
    \
    -netdev socket,id=dmz,listen=127.0.0.1:11003 \
    -device virtio-net-pci,netdev=dmz,mac=52:54:00:00:00:04 \
    \
    -display none \
    -serial "unix:$SERIAL_SOCK,server=on,wait=off" \
    -monitor "unix:$MONITOR,server,nowait" \
    -pidfile "$PIDFILE" \
    -daemonize

sleep 2
if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "[+] QEMU running as PID $(cat "$PIDFILE")"
    echo "[+] NICs: eth0=SLIRP-mgmt, eth1=WAN, eth2=LAN, eth3=DMZ"
else
    echo "[x] QEMU did not start" >&2
    exit 1
fi

echo "[+] Serial socket:      $SERIAL_SOCK"
echo "[+] Serial log (passive): $SERIAL_LOG"
echo "[+] QEMU monitor:       socat - UNIX-CONNECT:$MONITOR"
echo "[+] Dashboard (guest):  https://172.16.60.145:8443/"
