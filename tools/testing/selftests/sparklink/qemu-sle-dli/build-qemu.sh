#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Build QEMU with integrated usb-sle-dli device for SparkLink testing.
#
# Downloads QEMU source, patches it with the usb-sle-dli device,
# builds a minimal QEMU supporting x86_64 softmmu with USB.
#
# Usage:
#   ./build-qemu.sh              # Build QEMU
#   ./build-qemu.sh --clean      # Clean and rebuild
#   ./build-qemu.sh --download   # Download QEMU source only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
QEMU_VERSION="${QEMU_VERSION:-9.2.0}"
QEMU_URL="https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz"
WORK_DIR="$SCRIPT_DIR/.build"
QEMU_SRC="$WORK_DIR/qemu-${QEMU_VERSION}"
QEMU_BUILD="$WORK_DIR/build"
DEVICE_SRC="$SCRIPT_DIR/usb-sle-dli.c"
INSTALL_DIR="$SCRIPT_DIR/bin"
NPROC="$(nproc)"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
error() { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# -----------------------------------------------------------------------
# Step 1: Download QEMU source
# -----------------------------------------------------------------------
download_qemu() {
    if [[ -d "$QEMU_SRC" ]]; then
        info "QEMU source already exists at $QEMU_SRC"
        return 0
    fi

    mkdir -p "$WORK_DIR"
    local tarball="$WORK_DIR/qemu-${QEMU_VERSION}.tar.xz"

    if [[ ! -f "$tarball" ]]; then
        info "Downloading QEMU ${QEMU_VERSION}..."
        wget -q --show-progress -O "$tarball" "$QEMU_URL" || \
            curl -L -o "$tarball" "$QEMU_URL" || \
            error "Failed to download QEMU from $QEMU_URL"
    fi

    info "Extracting QEMU source..."
    tar -xf "$tarball" -C "$WORK_DIR"

    [[ -d "$QEMU_SRC" ]] || error "Extraction failed: $QEMU_SRC not found"
    info "QEMU source ready at $QEMU_SRC"
}

# -----------------------------------------------------------------------
# Step 2: Patch QEMU with usb-sle-dli device
# -----------------------------------------------------------------------
patch_qemu() {
    local dest="$QEMU_SRC/hw/usb/dev-sle-dli.c"

    if [[ ! -f "$DEVICE_SRC" ]]; then
        error "Device source not found: $DEVICE_SRC"
    fi

    info "Installing usb-sle-dli device into QEMU source..."
    cp "$DEVICE_SRC" "$dest"

    # Add the device to QEMU's USB Kconfig
    local kconfig="$QEMU_SRC/hw/usb/Kconfig"
    if ! grep -q "USB_SLE_DLI" "$kconfig" 2>/dev/null; then
        cat >> "$kconfig" << 'EOF'

config USB_SLE_DLI
    bool
    default y
    depends on USB
EOF
        info "  Added USB_SLE_DLI to hw/usb/Kconfig"
    fi

    # Add the device to meson.build
    local meson="$QEMU_SRC/hw/usb/meson.build"
    if ! grep -q "dev-sle-dli" "$meson" 2>/dev/null; then
        # Append to the softmmu_ss source list
        echo "" >> "$meson"
        echo "system_ss.add(when: 'CONFIG_USB_SLE_DLI', if_true: files('dev-sle-dli.c'))" >> "$meson"
        info "  Added dev-sle-dli.c to hw/usb/meson.build"
    fi

    info "QEMU source patched"
}

# -----------------------------------------------------------------------
# Step 3: Configure and build QEMU
# -----------------------------------------------------------------------
build_qemu() {
    info "Configuring QEMU (x86_64-softmmu only)..."

    mkdir -p "$QEMU_BUILD"
    cd "$QEMU_BUILD"

    "$QEMU_SRC/configure" \
        --target-list=x86_64-softmmu \
        --prefix="$INSTALL_DIR" \
        --disable-docs \
        --disable-gtk \
        --disable-sdl \
        --disable-opengl \
        --disable-virglrenderer \
        --enable-kvm \
        --disable-linux-aio \
        --disable-debug-info \
        --disable-werror \
        2>&1 | tail -5

    info "Building QEMU (${NPROC} jobs)..."
    make -j"$NPROC" 2>&1 | tail -5

    info "Installing to $INSTALL_DIR..."
    make install 2>&1 | tail -3

    local qemu_bin="$INSTALL_DIR/bin/qemu-system-x86_64"
    if [[ -x "$qemu_bin" ]]; then
        info "Build successful: $qemu_bin"
        "$qemu_bin" --version
    else
        error "Build failed: $qemu_bin not found"
    fi
}

# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------
case "${1:-}" in
    --clean)
        info "Cleaning build directory..."
        rm -rf "$QEMU_BUILD" "$INSTALL_DIR"
        download_qemu
        patch_qemu
        build_qemu
        ;;
    --download)
        download_qemu
        ;;
    *)
        download_qemu
        patch_qemu
        build_qemu
        ;;
esac

info "Done. Custom QEMU with usb-sle-dli is at:"
info "  $INSTALL_DIR/bin/qemu-system-x86_64"
info ""
info "Usage with SparkLink tests:"
info "  QEMU_BIN=$INSTALL_DIR/bin/qemu-system-x86_64 bash ../run_qemu_test.sh"
