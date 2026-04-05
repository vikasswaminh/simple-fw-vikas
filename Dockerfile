###############################################################################
# QuickFW Firewall Appliance ISO Builder
#
# Multi-stage build:
#   Stage 1: Compile Rust binaries (quickfw-api, quickfw-cli, quickfw-setup)
#   Stage 2: Build Debian live ISO with live-build
###############################################################################

# --- Stage 1: Build Rust binaries ---
FROM rust:1.83-bookworm AS rust-builder

RUN apt-get update && apt-get install -y \
    pkg-config libpcap-dev build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Build only QuickFW binaries (not the full GFW-RS suite)
RUN cargo build --release \
    -p quickfw-api \
    -p quickfw-cli \
    -p quickfw-setup \
    2>&1 | tail -30

# Strip binaries for minimal size
RUN strip target/release/quickfw-api \
         target/release/quickfw \
         target/release/quickfw-setup 2>/dev/null || true

RUN ls -lh target/release/quickfw-api target/release/quickfw target/release/quickfw-setup

# --- Stage 2: Build ISO ---
FROM debian:bookworm AS iso-builder

RUN apt-get update && apt-get install -y \
    live-build debootstrap xorriso syslinux-utils \
    isolinux syslinux-common dosfstools mtools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /iso

# Configure live-build — NO installer, live boot only
RUN lb config \
    --architectures amd64 \
    --distribution bookworm \
    --binary-images iso-hybrid \
    --debian-installer none \
    --debian-installer-gui false \
    --memtest none \
    --apt-recommends false \
    --bootappend-live "boot=live components hostname=quickfw toram" \
    --iso-application "QuickFW Firewall Appliance" \
    --iso-volume "QuickFW"

# Package list
RUN mkdir -p config/package-lists
RUN echo "nftables\n\
dnsmasq\n\
libpcap0.8\n\
ca-certificates\n\
openssh-server\n\
iproute2\n\
net-tools\n\
procps\n\
conntrack\n\
ethtool\n\
openssl\n\
kmod\n\
pciutils\n\
iputils-ping\n\
traceroute\n\
" > config/package-lists/quickfw.list.chroot

# Copy pre-built binaries from Stage 1
COPY --from=rust-builder /build/target/release/quickfw-api config/includes.chroot/usr/local/bin/quickfw-api
COPY --from=rust-builder /build/target/release/quickfw config/includes.chroot/usr/local/bin/quickfw
COPY --from=rust-builder /build/target/release/quickfw-setup config/includes.chroot/usr/local/bin/quickfw-setup

# Make binaries executable
RUN chmod 755 config/includes.chroot/usr/local/bin/quickfw-api \
              config/includes.chroot/usr/local/bin/quickfw \
              config/includes.chroot/usr/local/bin/quickfw-setup

# Copy web frontend
COPY front/ config/includes.chroot/opt/front/

# Copy rootfs overlay (sysctl, modprobe, systemd, nftables, etc.)
COPY rootfs/etc/ config/includes.chroot/etc/

# Copy recovery console and tuning scripts
COPY scripts/quickfw-console config/includes.chroot/usr/local/bin/quickfw-console
COPY scripts/quickfw-irq-tune config/includes.chroot/usr/local/bin/quickfw-irq-tune
RUN chmod 755 config/includes.chroot/usr/local/bin/quickfw-console \
              config/includes.chroot/usr/local/bin/quickfw-irq-tune

# Create config directory
RUN mkdir -p config/includes.chroot/etc/quickfw

# Build hook: enable services, set initial state
RUN mkdir -p config/hooks/live
RUN cat > config/hooks/live/0010-quickfw-setup.hook.chroot << 'HOOKEOF'
#!/bin/bash
set -e

# Enable core services
systemctl enable quickfw-setup.service 2>/dev/null || true
systemctl enable quickfw-api.service 2>/dev/null || true
systemctl enable quickfw-cli.service 2>/dev/null || true
systemctl enable quickfw-console.service 2>/dev/null || true
systemctl enable nftables.service 2>/dev/null || true

# Disable SSH by default
systemctl disable ssh.service 2>/dev/null || true

# Disable unnecessary timers
systemctl disable apt-daily.timer 2>/dev/null || true
systemctl disable apt-daily-upgrade.timer 2>/dev/null || true

# Create directories
mkdir -p /etc/quickfw
mkdir -p /opt/quickfw/front
mkdir -p /var/log/quickfw

# Set root password for live boot (setup wizard will force change)
echo "root:quickfw" | chpasswd

# Auto-login on tty1 (for setup wizard / CLI)
mkdir -p /etc/systemd/system/getty@tty1.service.d
cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf << 'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
EOF
HOOKEOF
RUN chmod 755 config/hooks/live/0010-quickfw-setup.hook.chroot

# ── BRANDING: ISOLINUX boot menu ──
RUN mkdir -p config/bootloaders/isolinux
RUN cat > config/bootloaders/isolinux/menu.cfg << 'MENUCFG'
menu hshift 0
menu width 82
menu title QuickFW Firewall Appliance
include stdmenu.cfg
include live.cfg
menu clear
MENUCFG

RUN cat > config/bootloaders/isolinux/live.cfg << 'LIVECFG'
label quickfw
	menu label ^QuickFW Firewall (Live)
	menu default
	linux /live/vmlinuz
	initrd /live/initrd.img
	append boot=live components hostname=quickfw toram

label quickfw-safe
	menu label QuickFW (Safe Mode)
	linux /live/vmlinuz
	initrd /live/initrd.img
	append boot=live components memtest noapic noapm nodma nomce nolapic nosmp nosplash vga=788
LIVECFG

RUN cat > config/bootloaders/isolinux/stdmenu.cfg << 'STDCFG'
menu background #1a1f36
menu color title        * #ff2563eb *
menu color border       * #40ffffff #1a1f36 std
menu color sel          * #ff1a1f36 #2563eb *
menu color unsel        * #ffffffff #1a1f36 std
menu color hotkey       * #ff2563eb #1a1f36 std
menu color hotsel       * #ffffffff #2563eb *
menu color tabmsg       * #80ffffff #1a1f36 std
menu color help         * #80ffffff #1a1f36 std
menu color timeout_msg  * #80ffffff #1a1f36 std
menu color timeout      * #ff2563eb #1a1f36 std
menu color cmdmark      * #ff2563eb #1a1f36 std
menu color cmdline      * #ffffffff #1a1f36 std
menu vshift 8
menu tabmsg Press ENTER to boot QuickFW or TAB to edit options
menu autoboot QuickFW starting in # seconds...
timeout 50
STDCFG

# Remove utilities submenu
RUN echo "" > config/bootloaders/isolinux/utilities.cfg 2>/dev/null || true

# ── BRANDING: GRUB boot menu ──
RUN mkdir -p config/bootloaders/grub-pc
RUN cat > config/bootloaders/grub-pc/grub.cfg << 'GRUBCFG'
if loadfont /boot/grub/font.pf2 ; then
    set gfxmode=auto
    insmod efi_gop
    insmod efi_uga
    insmod gfxterm
    terminal_output gfxterm
fi

set timeout=5
set default=0

set color_normal=white/black
set color_highlight=white/blue

menuentry "QuickFW Firewall (Live)" --hotkey=q {
	linux /live/vmlinuz boot=live components hostname=quickfw toram findiso=${iso_path}
	initrd /live/initrd.img
}

menuentry "QuickFW (Safe Mode)" {
	linux /live/vmlinuz boot=live components memtest noapic noapm nodma nomce nolapic nosmp nosplash vga=788
	initrd /live/initrd.img
}
GRUBCFG

# ── BRANDING: Remove Debian splash image, use text-only clean look ──
RUN rm -f config/bootloaders/isolinux/splash.png config/bootloaders/isolinux/splash800x600.png 2>/dev/null || true

# ── BRANDING: OS release info ──
RUN mkdir -p config/includes.chroot/etc
RUN cat > config/includes.chroot/etc/os-release << 'OSREL'
PRETTY_NAME="QuickFW 1.0"
NAME="QuickFW"
VERSION_ID="1.0"
VERSION="1.0 (Firewall Appliance)"
ID=quickfw
ID_LIKE=debian
HOME_URL="https://quickfw.io"
OSREL

# lb build needs --privileged (mount /proc, /dev/pts) so defer to runtime
CMD ["bash", "-c", "lb build 2>&1 | tail -100 && echo '--- ISO files found: ---' && find /iso -name '*.iso' -o -name '*.hybrid.iso' 2>/dev/null && ISO=$(find /iso -name '*.hybrid.iso' -o -name '*.iso' 2>/dev/null | head -1) && echo \"Copying $ISO\" && cp \"$ISO\" /output/quickfw.iso && echo 'ISO built successfully'"]
