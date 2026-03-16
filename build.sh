#!/bin/bash
###############################################################################
# QuickFW Firewall Appliance ISO Builder
#
# Builds a bootable Debian 12 (bookworm) ISO with QuickFW pre-installed.
# Uses Docker for reproducible builds.
#
# Usage: bash quickfw/build.sh
# Output: output/quickfw.iso
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
err() { echo -e "${RED}[x]${NC} $1"; exit 1; }

mkdir -p "$OUTPUT_DIR"

# Check for Docker
if ! command -v docker &>/dev/null; then
    err "Docker is required but not found. Install Docker and retry."
fi

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║    QuickFW ISO Builder                    ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

log "Building QuickFW Firewall Appliance ISO..."
info "Project root: $PROJECT_ROOT"
info "Output: $OUTPUT_DIR/quickfw.iso"
echo ""

# Step 1: Build the Docker image
log "Step 1/3: Building ISO builder Docker image..."
docker build \
    -f "$SCRIPT_DIR/Dockerfile" \
    -t quickfw-iso-builder \
    "$PROJECT_ROOT"

# Step 2: Run the builder container
log "Step 2/3: Running ISO build (this may take 10-30 minutes)..."
docker run --rm --privileged \
    -v "$OUTPUT_DIR:/output" \
    quickfw-iso-builder

# Step 3: Verify output
if [ -f "$OUTPUT_DIR/quickfw.iso" ]; then
    SIZE=$(du -h "$OUTPUT_DIR/quickfw.iso" | cut -f1)
    SHA=$(sha256sum "$OUTPUT_DIR/quickfw.iso" | cut -d' ' -f1)
    log "Step 3/3: ISO built successfully!"
    echo ""
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║  QuickFW Firewall Appliance ISO                      ║"
    echo "╠═══════════════════════════════════════════════════════╣"
    echo "║  File: $OUTPUT_DIR/quickfw.iso"
    echo "║  Size: $SIZE"
    echo "║  SHA256: ${SHA:0:32}..."
    echo "║"
    echo "║  Boot this ISO in a VM or write to USB:"
    echo "║    dd if=$OUTPUT_DIR/quickfw.iso of=/dev/sdX bs=4M status=progress"
    echo "║"
    echo "║  First boot: Setup wizard runs automatically."
    echo "║  Default admin: admin / quickfw"
    echo "║  Console: QuickFW CLI on tty1, Recovery on tty2"
    echo "╚═══════════════════════════════════════════════════════╝"

    # Generate checksum file
    sha256sum "$OUTPUT_DIR/quickfw.iso" > "$OUTPUT_DIR/quickfw.iso.sha256"
    log "Checksum written to $OUTPUT_DIR/quickfw.iso.sha256"
else
    err "ISO build failed — no output file found."
fi
