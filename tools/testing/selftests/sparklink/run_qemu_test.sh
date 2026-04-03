#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# sparklink QEMU integration test runner
#
# Builds the test program, creates a minimal initramfs, boots the
# kernel in QEMU, runs all sparklink test cases, and reports results.
#
# Requirements:
#   - qemu-system-x86_64
#   - busybox (static build)
#   - gcc (for test program compilation)
#   - Built kernel at $KBUILD (default: ../../build)
#
# Usage:
#   ./run_qemu_test.sh            # Run tests
#   ./run_qemu_test.sh --verbose  # Show full QEMU console output
#   QEMU_BIN=/path/to/custom/qemu-system-x86_64 ./run_qemu_test.sh
#   SLE_DLI_DEVICE=1 ./run_qemu_test.sh  # Enable usb-sle-dli device
#   SLE_DLI_DEVICE=2 ./run_qemu_test.sh  # Enable 2 usb-sle-dli devices (multi-device)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LINUX_SRC="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
KBUILD="${KBUILD:-$LINUX_SRC/build}"
BZIMAGE="$KBUILD/arch/x86/boot/bzImage"
WORKDIR="$SCRIPT_DIR/.qemu_test"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
SLE_DLI_DEVICE="${SLE_DLI_DEVICE:-1}"

VERBOSE=0
if [[ "${1:-}" == "--verbose" ]]; then
    VERBOSE=1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[FAIL]${NC}  $*"; }

cleanup() {
    rm -f "$SCRIPT_DIR/sparklink_test_static"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step 1: Verify prerequisites
# ---------------------------------------------------------------------------

info "Checking prerequisites..."

if [[ ! -f "$BZIMAGE" ]]; then
    error "Kernel image not found: $BZIMAGE"
    echo "  Build the kernel first: make O=build -j\$(nproc)"
    exit 1
fi

BUSYBOX="$(which busybox 2>/dev/null || true)"
if [[ -z "$BUSYBOX" ]]; then
    error "busybox not found (needed for initramfs)"
    echo "  Install: sudo apt install busybox-static"
    exit 1
fi

if ! file "$BUSYBOX" | grep -q "statically linked"; then
    error "busybox must be statically linked"
    exit 1
fi

if ! command -v qemu-system-x86_64 &>/dev/null; then
    error "qemu-system-x86_64 not found"
    echo "  Install: sudo apt install qemu-system-x86"
    exit 1
fi

info "  bzImage: $BZIMAGE"
info "  busybox: $BUSYBOX"

# ---------------------------------------------------------------------------
# Step 2: Build test program (static)
# ---------------------------------------------------------------------------

info "Building sparklink_test (static)..."

TEST_SRC="$SCRIPT_DIR/sparklink_test.c"
TEST_BIN="$SCRIPT_DIR/sparklink_test_static"

# Resolve kernel source tree root (four levels up from selftests/sparklink)
KERNEL_SRC="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

# Symlink UAPI header into the test directory for local include
UAPI_HEADER="$KERNEL_SRC/include/uapi/linux/sparklink_ioctl.h"
SYMLINK_TARGET="$SCRIPT_DIR/sparklink_ioctl.h"
if [ ! -e "$SYMLINK_TARGET" ] && [ -f "$UAPI_HEADER" ]; then
	ln -sf "$UAPI_HEADER" "$SYMLINK_TARGET"
fi

gcc -Wall -Wextra -O2 -static \
    -o "$TEST_BIN" "$TEST_SRC"

info "  Built: $TEST_BIN"

# ---------------------------------------------------------------------------
# Step 3: Create minimal initramfs
# ---------------------------------------------------------------------------

info "Creating initramfs..."

mkdir -p "$WORKDIR/initramfs"/{bin,dev,proc,sys,tmp}

# Copy busybox
cp "$BUSYBOX" "$WORKDIR/initramfs/bin/busybox"
chmod 755 "$WORKDIR/initramfs/bin/busybox"

# Create busybox symlinks
for cmd in sh cat echo ls mkdir mount umount mdev sleep poweroff; do
    ln -sf busybox "$WORKDIR/initramfs/bin/$cmd"
done

# Copy test binary
cp "$TEST_BIN" "$WORKDIR/initramfs/bin/sparklink_test"
chmod 755 "$WORKDIR/initramfs/bin/sparklink_test"

# Create init script
cat > "$WORKDIR/initramfs/init" << 'INIT_EOF'
#!/bin/sh
# Minimal init for sparklink QEMU test

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev 2>/dev/null || mdev -s
mount -t debugfs none /sys/kernel/debug 2>/dev/null

echo "========================================"
echo "SparkLink QEMU Integration Test"
echo "========================================"
echo ""

# Wait for /dev/sparklink to appear
RETRY=0
MAX_RETRY=30
while [ ! -c /dev/sparklink ] && [ $RETRY -lt $MAX_RETRY ]; do
    sleep 0.1
    RETRY=$((RETRY + 1))
done

if [ ! -c /dev/sparklink ]; then
    echo "QEMU_TEST_RESULT: FAIL (device /dev/sparklink not found)"
    echo ""
    echo "Available devices:"
    ls -la /dev/ 2>/dev/null | head -20
    echo ""
    echo "Kernel log:"
    cat /proc/kmsg 2>/dev/null | head -30 || dmesg 2>/dev/null | head -30
    poweroff -f
    exit 1
fi

echo "Device /dev/sparklink found"
echo ""

# If USB SLE DLI devices are expected, wait for them to enumerate
# Check if any USB SLE DLI devices appear in /sys
RETRY=0
MAX_USB_RETRY=50
while [ $RETRY -lt $MAX_USB_RETRY ]; do
    USB_COUNT=$(find /sys/bus/usb/devices/ -name "idProduct" -exec cat {} \; 2>/dev/null | grep -c "5678" || true)
    BOUND_COUNT=$(find /sys/bus/usb/drivers/sparklink_usb/ -mindepth 1 -maxdepth 1 -type l 2>/dev/null | wc -l || echo 0)
    if [ "$USB_COUNT" -gt 0 ] && [ "$BOUND_COUNT" -ge "$USB_COUNT" ]; then
        echo "USB SLE DLI devices: $USB_COUNT found, $BOUND_COUNT bound"
        break
    fi
    sleep 0.1
    RETRY=$((RETRY + 1))
done

# Run the test suite
/bin/sparklink_test 2>&1
TEST_EXIT=$?

echo ""
echo "========================================"
if [ $TEST_EXIT -eq 0 ]; then
    echo "QEMU_TEST_RESULT: PASS (exit=$TEST_EXIT)"
else
    echo "QEMU_TEST_RESULT: FAIL (exit=$TEST_EXIT)"
fi
echo "========================================"

# Power off the VM
poweroff -f
INIT_EOF

chmod 755 "$WORKDIR/initramfs/init"

# Build initramfs cpio
(cd "$WORKDIR/initramfs" && find . | cpio -o -H newc --quiet 2>/dev/null | gzip) > "$WORKDIR/initramfs.cpio.gz"

INITRAMFS_SIZE=$(du -h "$WORKDIR/initramfs.cpio.gz" | cut -f1)
info "  initramfs: $WORKDIR/initramfs.cpio.gz ($INITRAMFS_SIZE)"

# ---------------------------------------------------------------------------
# Step 4: Run QEMU
# ---------------------------------------------------------------------------

CONSOLE_LOG="$WORKDIR/console.log"
TIMEOUT=120

info "Starting QEMU (timeout=${TIMEOUT}s)..."

# Detect KVM support
KVM_OPTS=""
if [[ -r /dev/kvm ]]; then
    KVM_OPTS="-enable-kvm"
fi

# Detect custom QEMU with usb-sle-dli support
SLE_USB_OPTS=""
CUSTOM_QEMU_DIR="$SCRIPT_DIR/qemu-sle-dli/bin/bin"
if [[ "$SLE_DLI_DEVICE" != "0" ]]; then
    # Determine number of SLE DLI devices (1 if just "1", otherwise the value)
    SLE_DEV_COUNT=1
    if [[ "$SLE_DLI_DEVICE" =~ ^[0-9]+$ ]] && (( SLE_DLI_DEVICE > 1 )); then
        SLE_DEV_COUNT="$SLE_DLI_DEVICE"
    fi

    # Use custom QEMU if built, otherwise warn
    if [[ -x "$CUSTOM_QEMU_DIR/qemu-system-x86_64" ]]; then
        QEMU_BIN="$CUSTOM_QEMU_DIR/qemu-system-x86_64"
        SLE_USB_OPTS="-device qemu-xhci,id=xhci"
        for (( i=0; i<SLE_DEV_COUNT; i++ )); do
            SLE_USB_OPTS+=" -device usb-sle-dli,bus=xhci.0"
        done
        info "Using custom QEMU with $SLE_DEV_COUNT usb-sle-dli device(s)"
    elif "$QEMU_BIN" -device help 2>&1 | grep -q usb-sle-dli; then
        SLE_USB_OPTS="-device qemu-xhci,id=xhci"
        for (( i=0; i<SLE_DEV_COUNT; i++ )); do
            SLE_USB_OPTS+=" -device usb-sle-dli,bus=xhci.0"
        done
        info "System QEMU supports usb-sle-dli"
    else
        warn "usb-sle-dli device not available; running without virtual controller"
        warn "Build custom QEMU: cd qemu-sle-dli && ./build-qemu.sh"
    fi
fi

set +e
timeout "$TIMEOUT" "$QEMU_BIN" \
    -kernel "$BZIMAGE" \
    -initrd "$WORKDIR/initramfs.cpio.gz" \
    -append "console=ttyS0 earlyprintk=serial panic=1 oops=panic" \
    -serial "file:$CONSOLE_LOG" \
    -display none \
    -no-reboot \
    -m 256M \
    -smp 2 \
    $KVM_OPTS \
    $SLE_USB_OPTS \
    2>/dev/null
QEMU_EXIT=$?
set -e

if [[ $VERBOSE -eq 1 ]] && [[ -f "$CONSOLE_LOG" ]]; then
    cat "$CONSOLE_LOG"
fi

# ---------------------------------------------------------------------------
# Step 5: Analyze results
# ---------------------------------------------------------------------------

echo ""
info "Analyzing results..."

if [[ $QEMU_EXIT -eq 124 ]]; then
    error "QEMU timed out after ${TIMEOUT}s"
    if [[ $VERBOSE -eq 1 ]]; then
        echo "--- Console log ---"
        cat "$CONSOLE_LOG"
        echo "--- End log ---"
    fi
    exit 1
fi

# Extract test result
RESULT_LINE=$(grep "QEMU_TEST_RESULT:" "$CONSOLE_LOG" 2>/dev/null || true)
if [[ -z "$RESULT_LINE" ]]; then
    error "No test result found in console output"
    if [[ $VERBOSE -eq 0 ]]; then
        echo "  Run with --verbose to see full output"
    fi
    exit 1
fi

# Count OK/FAIL/WARN lines (anchor to line start to avoid kernel log noise)
OK_COUNT=$(grep -c "^  OK:" "$CONSOLE_LOG" 2>/dev/null || true)
FAIL_COUNT=$(grep -c "^  FAIL:" "$CONSOLE_LOG" 2>/dev/null || true)
WARN_COUNT=$(grep -c "^  WARN:" "$CONSOLE_LOG" 2>/dev/null || true)

echo ""
echo "Test results: ${OK_COUNT} OK, ${FAIL_COUNT} FAIL, ${WARN_COUNT} WARN"

if echo "$RESULT_LINE" | grep -q "PASS"; then
    info "All tests PASSED"
    exit 0
else
    error "Tests FAILED"
    # Show failed lines
    grep "  FAIL:" "$CONSOLE_LOG" 2>/dev/null || true
    exit 1
fi
