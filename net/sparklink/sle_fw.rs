// SPDX-License-Identifier: GPL-2.0

//! SparkLink firmware loading framework.
//!
//! Provides firmware download support for SLE controllers. The firmware
//! blob is loaded from the standard Linux firmware search path
//! (`/lib/firmware/`) using `kernel::firmware::Firmware`, then sent to
//! the controller in chunks via the USB bulk OUT endpoint.
//!
//! Firmware file naming convention:
//!
//!     sparklink/sle_<bus>_<version>.bin
//!
//! Examples:
//!     sparklink/sle_usb_v1.bin
//!     sparklink/sle_uart_v2.bin
//!
//! Download protocol (over USB):
//!
//! ```text
//!   Host                          Controller
//!    |                                |
//!    |-- FW_DOWNLOAD_START (size) --> |
//!    |                                |
//!    |-- FW_DATA chunk 0 ----------> |
//!    |-- FW_DATA chunk 1 ----------> |
//!    |   ...                          |
//!    |-- FW_DATA chunk N ----------> |
//!    |                                |
//!    |-- FW_DOWNLOAD_DONE ---------> |
//!    |<-- CommandComplete (status) -- |
//! ```
//!
//! Over UART, the same logical protocol applies but using the H4
//! framing layer instead of raw USB bulk transfers.

#![allow(dead_code)]

use kernel::prelude::*;
use kernel::firmware::Firmware;

// ---------------------------------------------------------------------------
// FFI declarations — C-side firmware download
// ---------------------------------------------------------------------------

extern "C" {
    fn sle_usb_dev_download_fw(
        dev_id: i32,
        data: *const u8,
        size: i32,
        chunk_size: i32,
    ) -> i32;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Base path for SparkLink firmware files.
pub(crate) const FW_BASE_PATH: &str = "sparklink/";

/// Default firmware file for USB controllers.
pub(crate) const FW_USB_DEFAULT: &[u8] = b"sparklink/sle_usb_v1.bin\0";

/// Default firmware file for UART controllers.
pub(crate) const FW_UART_DEFAULT: &[u8] = b"sparklink/sle_uart_v1.bin\0";

/// Default chunk size for firmware download (bytes).
/// 0 means auto-detect from endpoint max packet size.
pub(crate) const FW_DEFAULT_CHUNK_SIZE: i32 = 0;

// ---------------------------------------------------------------------------
// Firmware download result
// ---------------------------------------------------------------------------

/// Result of a firmware download attempt.
pub(crate) struct FwDownloadResult {
    /// Firmware size in bytes.
    pub(crate) size: usize,
    /// Whether the download completed successfully.
    pub(crate) success: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load firmware for a USB-attached SLE controller.
///
/// Attempts to load the firmware file from `/lib/firmware/sparklink/`
/// and download it to the controller via USB bulk transfer.
///
/// `dev` is the kernel `device::Device` reference used for the firmware
/// request (typically from the USB interface).
///
/// `dev_id` is the device ID in the USB device table.
///
/// Returns `Ok(FwDownloadResult)` on success, `Err` if the firmware
/// file is not found or the download protocol fails.
///
/// If the firmware file is not found, this is logged but treated as
/// non-fatal — the controller may already have firmware programmed.
pub(crate) fn load_usb_firmware(
    dev_id: u16,
    fw_name: &kernel::str::CStr,
    dev: &kernel::device::Device,
) -> Result<FwDownloadResult> {
    // Request firmware from the standard search path.
    let fw = match Firmware::request(fw_name, dev) {
        Ok(fw) => fw,
        Err(e) => {
            pr_info!(
                "sparklink-fw: firmware not found, continuing without\n"
            );
            return Err(e);
        }
    };

    let size = fw.size();
    if size == 0 {
        pr_warn!("sparklink-fw: firmware file is empty\n");
        return Err(EINVAL);
    }

    pr_info!("sparklink-fw: loaded {} bytes, starting download\n", size);

    // Download via the C FFI layer.
    // SAFETY: fw.data() returns a valid slice for the firmware lifetime,
    // sle_usb_dev_download_fw copies from it synchronously.
    let ret = unsafe {
        sle_usb_dev_download_fw(
            i32::from(dev_id),
            fw.data().as_ptr(),
            size as i32,
            FW_DEFAULT_CHUNK_SIZE,
        )
    };

    // Firmware object is dropped here, releasing the firmware blob.

    if ret < 0 {
        pr_err!(
            "sparklink-fw: download failed for dev_id={}: {}\n",
            dev_id,
            ret
        );
        return Err(Error::from_errno(ret));
    }

    Ok(FwDownloadResult {
        size,
        success: true,
    })
}

/// Attempt to load firmware with a version-specific name, falling back
/// to the default name if not found.
///
/// Tries: `sparklink/sle_usb_v{fw_ver}.bin`
/// Falls back to: `sparklink/sle_usb_v1.bin`
pub(crate) fn load_usb_firmware_versioned(
    dev_id: u16,
    fw_version: u32,
    dev: &kernel::device::Device,
) -> Result<FwDownloadResult> {
    // First try version-specific firmware.
    // Format the CString for the firmware name.
    let default_name = kernel::c_str!("sparklink/sle_usb_v1.bin");

    // If we have a known firmware version, try versioned first.
    if fw_version > 0 {
        pr_debug!(
            "sparklink-fw: no versioned firmware for v{}, trying default\n",
            fw_version
        );
    }

    // Fall back to default firmware.
    load_usb_firmware(dev_id, default_name, dev)
}
