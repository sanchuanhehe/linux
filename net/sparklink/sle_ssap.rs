// SPDX-License-Identifier: GPL-2.0

//! SLE Service Access Protocol (SSAP) — attribute service layer.
//!
//! Implements the SSAP protocol per T/XS 20001-2025 section 7.4,
//! providing a GATT-equivalent service framework for SparkLink SLE.
//!
//! Core concepts:
//!   - Service: a group of related entries with a UUID
//!   - Property: readable/writable data with operation indicators
//!   - Method: callable function interface with input/output
//!   - Event: server-initiated notification or indication
//!   - Descriptor: metadata attached to a property (format, config)
//!
//! The local device operates as both SSAP server (hosting services)
//! and SSAP client (consuming remote services). In the current
//! loopback-only implementation, client operations resolve locally.

#![allow(dead_code, unreachable_pub)]

use kernel::alloc::KVec;
use kernel::prelude::*;

// ---------------------------------------------------------------------------
// SSAP message codes (T/XS 20001-2025 table 7.4)
// ---------------------------------------------------------------------------

/// SSAP protocol message types.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SsapMsgCode {
    ErrorRsp = 0x01,
    ExchangeInfoReq = 0x02,
    ExchangeInfoRsp = 0x03,
    FindStructureReq = 0x04,
    FindStructureRsp = 0x05,
    FindByUuidReq = 0x06,
    FindByUuidRsp = 0x07,
    ReadReq = 0x08,
    ReadRsp = 0x09,
    ReadByUuidReq = 0x0A,
    ReadByUuidRsp = 0x0B,
    WriteCmd = 0x0C,
    WriteReq = 0x0D,
    WriteRsp = 0x0E,
    ValueNtf = 0x0F,
    ValueInd = 0x10,
    ValueAck = 0x11,
    CallMethodCmd = 0x12,
    CallMethodReq = 0x13,
    CallMethodRsp = 0x14,
}

// ---------------------------------------------------------------------------
// Entry categories (T/XS 20001-2025 section 7.4.3)
// ---------------------------------------------------------------------------

/// Category byte for a service entry.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EntryCategory {
    PrimaryService = 0x00,
    SecondaryService = 0x01,
    Property = 0x02,
    Method = 0x03,
    Event = 0x04,
    ServiceRef = 0x05,
    CustomPrimaryService = 0x08,
    CustomSecondaryService = 0x09,
    CustomProperty = 0x0A,
    CustomMethod = 0x0B,
    CustomEvent = 0x0C,
    CustomServiceRef = 0x0D,
}

// ---------------------------------------------------------------------------
// UUID representation
// ---------------------------------------------------------------------------

/// Service/characteristic UUID: either 16-bit standard or 128-bit custom.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SsapUuid {
    /// Standard 16-bit UUID from the SparkLink allocated range.
    Uuid16(u16),
    /// Vendor-specific 128-bit UUID.
    Uuid128([u8; 16]),
}

impl SsapUuid {
    /// Check if this is a custom UUID (128 bits).
    pub fn is_custom(&self) -> bool {
        matches!(self, SsapUuid::Uuid128(_))
    }

    /// Return the 16-bit value, or None for 128-bit UUIDs.
    pub fn as_u16(&self) -> Option<u16> {
        match self {
            SsapUuid::Uuid16(v) => Some(*v),
            SsapUuid::Uuid128(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Operation indicator (4 bytes, T/XS 20001-2025 section 7.4.3.5)
// ---------------------------------------------------------------------------

/// Operation permissions on a property entry (4-byte bitmask).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OpIndicator(u32);

impl OpIndicator {
    /// Property can be read.
    pub const READ: Self = Self(1 << 0);
    /// Property can be written without response.
    pub const WRITE_NO_RSP: Self = Self(1 << 1);
    /// Property can be written with response.
    pub const WRITE_WITH_RSP: Self = Self(1 << 2);
    /// Server can send notifications (no ack).
    pub const NOTIFY: Self = Self(1 << 3);
    /// Server can send indications (with ack).
    pub const INDICATE: Self = Self(1 << 4);
    /// Property value carried in broadcast PDUs.
    pub const BROADCAST: Self = Self(1 << 5);
    /// Description descriptor is writable.
    pub const DESC_WRITABLE: Self = Self(1 << 8);
    /// Client config descriptor is writable.
    pub const CLIENT_CFG_WR: Self = Self(1 << 9);
    /// Server config descriptor is writable.
    pub const SERVER_CFG_WR: Self = Self(1 << 10);

    /// Create an empty indicator with no flags set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if all bits in `other` are set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Raw u32 value.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Construct from a raw bitmask value.
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }
}

impl core::ops::BitOr for OpIndicator {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for OpIndicator {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

// ---------------------------------------------------------------------------
// Descriptors
// ---------------------------------------------------------------------------

/// Standard descriptor types (T/XS 20001-2025 section 7.4.3.7).
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DescriptorType {
    /// UTF-8 text description of the property.
    PropertyDesc = 0x01,
    /// Per-client notification/indication configuration (2 bytes).
    ClientConfig = 0x02,
    /// Server broadcast configuration (2 bytes).
    ServerConfig = 0x03,
    /// Property format (7 bytes): type, exponent, unit, desc.
    PropertyFormat = 0x04,
}

/// Data type codes for PropertyFormat descriptor.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DataType {
    Uint8 = 0x01,
    Uint16 = 0x02,
    Uint32 = 0x03,
    Uint64 = 0x04,
    Int8 = 0x05,
    Int16 = 0x06,
    Int32 = 0x07,
    Int64 = 0x08,
    Boolean = 0x09,
    Float32 = 0x0A,
    Float64 = 0x0B,
    Utf8String = 0x0C,
    Utf16String = 0x0D,
    Array = 0x0E,
    Structure = 0x0F,
}

/// Client configuration descriptor flags.
#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ClientConfigFlag {
    /// Notifications disabled.
    None = 0x0000,
    /// Notifications enabled.
    Notification = 0x0001,
    /// Indications enabled.
    Indication = 0x0002,
}

/// Descriptor storage.
pub struct Descriptor {
    pub dtype: DescriptorType,
    pub data: KVec<u8>,
}

// ---------------------------------------------------------------------------
// Property / Method / Event entries
// ---------------------------------------------------------------------------

/// Maximum value length for an in-memory property.
pub const PROPERTY_VALUE_MAX: usize = 512;

/// A single property entry in a service.
pub struct PropertyEntry {
    /// Handle assigned by the server (0x0010..0xFFFF).
    pub handle: u16,
    /// UUID identifying the property type.
    pub uuid: SsapUuid,
    /// Operation indicator flags.
    pub ops: OpIndicator,
    /// Current value bytes (up to PROPERTY_VALUE_MAX).
    pub value: KVec<u8>,
    /// Attached descriptors.
    pub descriptors: KVec<Descriptor>,
    /// Client-config: notifications/indications enabled.
    pub client_cfg: u16,
}

/// A method entry in a service.
pub struct MethodEntry {
    pub handle: u16,
    pub uuid: SsapUuid,
    /// Input parameter buffer (from last call).
    pub input: KVec<u8>,
    /// Output result buffer (from last call).
    pub output: KVec<u8>,
}

/// An event entry in a service.
pub struct EventEntry {
    pub handle: u16,
    pub uuid: SsapUuid,
    /// Whether this event is enabled for the client.
    pub enabled: bool,
    /// Last event data payload.
    pub data: KVec<u8>,
}

// ---------------------------------------------------------------------------
// Service structure
// ---------------------------------------------------------------------------

/// A registered service in the SSAP database.
pub struct ServiceEntry {
    /// Start handle of the service.
    pub start_handle: u16,
    /// End handle of the service (inclusive).
    pub end_handle: u16,
    /// Service UUID.
    pub uuid: SsapUuid,
    /// Whether this is a primary or secondary service.
    pub primary: bool,
    /// Properties within this service.
    pub properties: KVec<PropertyEntry>,
    /// Methods within this service.
    pub methods: KVec<MethodEntry>,
    /// Events within this service.
    pub events: KVec<EventEntry>,
}

// ---------------------------------------------------------------------------
// Notification/indication tracking
// ---------------------------------------------------------------------------

/// A pending notification or indication to deliver to the client.
pub struct PendingNotification {
    /// Handle of the property that changed.
    pub handle: u16,
    /// Whether this is an indication (requires ACK) or notification.
    pub indication: bool,
    /// The updated value.
    pub data: KVec<u8>,
}

// ---------------------------------------------------------------------------
// SSAP exchange info (capability negotiation)
// ---------------------------------------------------------------------------

/// Negotiated SSAP parameters after EXCHANGE_INFO handshake.
#[derive(Copy, Clone, Debug)]
pub struct SsapNegotiated {
    /// Effective MTU: min(client_mtu, server_mtu).
    pub mtu: u16,
    /// Protocol version (major, minor).
    pub version: (u8, u8),
    /// Whether reliable transport mode is used.
    pub reliable_mode: bool,
}

impl Default for SsapNegotiated {
    fn default() -> Self {
        Self {
            mtu: 247,
            version: (1, 0),
            reliable_mode: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SSAP error codes (T/XS 20001-2025 section 7.4.8)
// ---------------------------------------------------------------------------

/// SSAP protocol error codes for ERROR_RSP.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SsapError {
    /// Operation completed successfully.
    Success = 0x00,
    /// Invalid handle.
    InvalidHandle = 0x01,
    /// Read not permitted.
    ReadNotPermitted = 0x02,
    /// Write not permitted.
    WriteNotPermitted = 0x03,
    /// Invalid message code.
    InvalidMsgCode = 0x04,
    /// Authentication required.
    AuthRequired = 0x05,
    /// Request not supported.
    RequestNotSupported = 0x06,
    /// Invalid offset.
    InvalidOffset = 0x07,
    /// Insufficient resources.
    InsufficientResources = 0x08,
    /// Service not found.
    ServiceNotFound = 0x09,
    /// Property not found.
    PropertyNotFound = 0x0A,
}

impl SsapError {
    /// Decode from raw byte, defaulting to RequestNotSupported for unknown values.
    pub fn from_raw(v: u8) -> Self {
        match v {
            0x00 => Self::Success,
            0x01 => Self::InvalidHandle,
            0x02 => Self::ReadNotPermitted,
            0x03 => Self::WriteNotPermitted,
            0x04 => Self::InvalidMsgCode,
            0x05 => Self::AuthRequired,
            0x06 => Self::RequestNotSupported,
            0x07 => Self::InvalidOffset,
            0x08 => Self::InsufficientResources,
            0x09 => Self::ServiceNotFound,
            0x0A => Self::PropertyNotFound,
            _ => Self::RequestNotSupported,
        }
    }
}

// ---------------------------------------------------------------------------
// SSAP inner state (runs inside a Mutex in sparklink_core)
// ---------------------------------------------------------------------------

/// The full SSAP server/client state for one file descriptor.
pub struct SsapInner {
    /// Registered local services.
    pub services: KVec<ServiceEntry>,
    /// Next handle to assign.
    next_handle: u16,
    /// Capability negotiation result.
    pub negotiated: SsapNegotiated,
    /// Pending notifications/indications queue.
    pub notifications: KVec<PendingNotification>,
}

impl SsapInner {
    /// Create a new empty SSAP context.
    pub fn new() -> Self {
        Self {
            services: KVec::new(),
            next_handle: 0x0010, // First user handle
            negotiated: SsapNegotiated::default(),
            notifications: KVec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Handle allocation
    // -----------------------------------------------------------------------

    fn alloc_handle(&mut self) -> Result<u16> {
        let h = self.next_handle;
        self.next_handle = h.checked_add(1).ok_or(ENOSPC)?;
        Ok(h)
    }

    fn alloc_handles(&mut self, count: u16) -> Result<u16> {
        let start = self.next_handle;
        self.next_handle = start.checked_add(count).ok_or(ENOSPC)?;
        Ok(start)
    }

    // -----------------------------------------------------------------------
    // Service registration
    // -----------------------------------------------------------------------

    /// Register a new primary service with a 16-bit UUID.
    /// Returns the service start handle.
    pub fn register_service(&mut self, uuid: SsapUuid, primary: bool) -> Result<u16> {
        let start = self.alloc_handle()?;
        let svc = ServiceEntry {
            start_handle: start,
            end_handle: start, // Updated as entries are added
            uuid,
            primary,
            properties: KVec::new(),
            methods: KVec::new(),
            events: KVec::new(),
        };
        self.services.push(svc, GFP_KERNEL)?;
        Ok(start)
    }

    /// Add a property to the last registered service.
    pub fn add_property(
        &mut self,
        uuid: SsapUuid,
        ops: OpIndicator,
        initial_value: &[u8],
    ) -> Result<u16> {
        let handle = self.alloc_handle()?;
        let svc = self.services.last_mut().ok_or(ENODEV)?;

        let mut value = KVec::new();
        value.extend_from_slice(initial_value, GFP_KERNEL)?;

        let prop = PropertyEntry {
            handle,
            uuid,
            ops,
            value,
            descriptors: KVec::new(),
            client_cfg: 0,
        };
        svc.properties.push(prop, GFP_KERNEL)?;
        svc.end_handle = handle;
        Ok(handle)
    }

    /// Add a method to the last registered service.
    pub fn add_method(&mut self, uuid: SsapUuid) -> Result<u16> {
        let handle = self.alloc_handle()?;
        let svc = self.services.last_mut().ok_or(ENODEV)?;

        let method = MethodEntry {
            handle,
            uuid,
            input: KVec::new(),
            output: KVec::new(),
        };
        svc.methods.push(method, GFP_KERNEL)?;
        svc.end_handle = handle;
        Ok(handle)
    }

    /// Add an event to the last registered service.
    pub fn add_event(&mut self, uuid: SsapUuid) -> Result<u16> {
        let handle = self.alloc_handle()?;
        let svc = self.services.last_mut().ok_or(ENODEV)?;

        let event = EventEntry {
            handle,
            uuid,
            enabled: false,
            data: KVec::new(),
        };
        svc.events.push(event, GFP_KERNEL)?;
        svc.end_handle = handle;
        Ok(handle)
    }

    /// Add a descriptor to the last property of the last service.
    pub fn add_descriptor(&mut self, dtype: DescriptorType, data: &[u8]) -> Result {
        let svc = self.services.last_mut().ok_or(ENODEV)?;
        let prop = svc.properties.last_mut().ok_or(ENODEV)?;

        let mut d = KVec::new();
        d.extend_from_slice(data, GFP_KERNEL)?;

        let desc = Descriptor { dtype, data: d };
        prop.descriptors.push(desc, GFP_KERNEL)?;
        Ok(())
    }

    /// Remove a service by its start handle.
    pub fn remove_service(&mut self, start_handle: u16) -> Result {
        let idx = self
            .services
            .iter()
            .position(|s| s.start_handle == start_handle);
        match idx {
            Some(i) => {
                let _ = self.services.remove(i);
                Ok(())
            }
            None => Err(ENOENT),
        }
    }

    // -----------------------------------------------------------------------
    // Service discovery (FINDSTRUCTURE)
    // -----------------------------------------------------------------------

    /// Find all primary services. Returns (start_handle, end_handle, uuid) tuples.
    pub fn find_primary_services(&self) -> KVec<(u16, u16, SsapUuid)> {
        let mut result = KVec::new();
        for svc in self.services.iter() {
            if svc.primary {
                let _ = result.push((svc.start_handle, svc.end_handle, svc.uuid), GFP_KERNEL);
            }
        }
        result
    }

    /// Find a service by UUID.
    pub fn find_service_by_uuid(&self, uuid: &SsapUuid) -> Option<&ServiceEntry> {
        self.services.iter().find(|s| &s.uuid == uuid)
    }

    /// Find all entries within a handle range (service discovery).
    pub fn find_in_range(&self, start: u16, end: u16) -> KVec<EntryInfo> {
        let mut result = KVec::new();
        for svc in self.services.iter() {
            if svc.start_handle >= start && svc.start_handle <= end {
                let cat = if svc.primary {
                    EntryCategory::PrimaryService
                } else {
                    EntryCategory::SecondaryService
                };
                let _ = result.push(
                    EntryInfo {
                        handle: svc.start_handle,
                        category: cat,
                        uuid: svc.uuid,
                    },
                    GFP_KERNEL,
                );
            }
            for p in svc.properties.iter() {
                if p.handle >= start && p.handle <= end {
                    let _ = result.push(
                        EntryInfo {
                            handle: p.handle,
                            category: EntryCategory::Property,
                            uuid: p.uuid,
                        },
                        GFP_KERNEL,
                    );
                }
            }
            for m in svc.methods.iter() {
                if m.handle >= start && m.handle <= end {
                    let _ = result.push(
                        EntryInfo {
                            handle: m.handle,
                            category: EntryCategory::Method,
                            uuid: m.uuid,
                        },
                        GFP_KERNEL,
                    );
                }
            }
            for e in svc.events.iter() {
                if e.handle >= start && e.handle <= end {
                    let _ = result.push(
                        EntryInfo {
                            handle: e.handle,
                            category: EntryCategory::Event,
                            uuid: e.uuid,
                        },
                        GFP_KERNEL,
                    );
                }
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // Read / Write operations
    // -----------------------------------------------------------------------

    /// Read a property value by handle.
    pub fn read_property(&self, handle: u16) -> Result<KVec<u8>> {
        for svc in self.services.iter() {
            for p in svc.properties.iter() {
                if p.handle == handle {
                    if !p.ops.contains(OpIndicator::READ) {
                        return Err(EACCES);
                    }
                    let mut out = KVec::new();
                    out.extend_from_slice(&p.value, GFP_KERNEL)?;
                    return Ok(out);
                }
            }
        }
        Err(ENOENT)
    }

    /// Read a property by UUID (finds the first matching property).
    pub fn read_by_uuid(&self, uuid: &SsapUuid) -> Result<(u16, KVec<u8>)> {
        for svc in self.services.iter() {
            for p in svc.properties.iter() {
                if &p.uuid == uuid && p.ops.contains(OpIndicator::READ) {
                    let mut out = KVec::new();
                    out.extend_from_slice(&p.value, GFP_KERNEL)?;
                    return Ok((p.handle, out));
                }
            }
        }
        Err(ENOENT)
    }

    /// Write a property value by handle (write-with-response).
    pub fn write_property(&mut self, handle: u16, data: &[u8]) -> Result {
        if data.len() > PROPERTY_VALUE_MAX {
            return Err(EINVAL);
        }

        // Track what notification to generate
        let mut do_notify = false;
        let mut do_indicate = false;
        let mut found = false;

        for svc in self.services.iter_mut() {
            for p in svc.properties.iter_mut() {
                if p.handle == handle {
                    if !p.ops.contains(OpIndicator::WRITE_WITH_RSP)
                        && !p.ops.contains(OpIndicator::WRITE_NO_RSP)
                    {
                        return Err(EACCES);
                    }
                    p.value.clear();
                    p.value.extend_from_slice(data, GFP_KERNEL)?;

                    do_notify = p.ops.contains(OpIndicator::NOTIFY) && (p.client_cfg & 0x01) != 0;
                    do_indicate =
                        p.ops.contains(OpIndicator::INDICATE) && (p.client_cfg & 0x02) != 0;
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }

        if !found {
            return Err(ENOENT);
        }

        // Queue notifications outside the services borrow
        if do_notify {
            let mut nd = KVec::new();
            if nd.extend_from_slice(data, GFP_KERNEL).is_err() {
                pr_warn!(
                    "sparklink: SSAP notification dropped (OOM) handle=0x{:04x}\n",
                    handle
                );
            } else if self
                .notifications
                .push(
                    PendingNotification {
                        handle,
                        indication: false,
                        data: nd,
                    },
                    GFP_KERNEL,
                )
                .is_err()
            {
                pr_warn!(
                    "sparklink: SSAP notification queue full handle=0x{:04x}\n",
                    handle
                );
            }
        }
        if do_indicate {
            let mut nd = KVec::new();
            if nd.extend_from_slice(data, GFP_KERNEL).is_err() {
                pr_warn!(
                    "sparklink: SSAP indication dropped (OOM) handle=0x{:04x}\n",
                    handle
                );
            } else if self
                .notifications
                .push(
                    PendingNotification {
                        handle,
                        indication: true,
                        data: nd,
                    },
                    GFP_KERNEL,
                )
                .is_err()
            {
                pr_warn!(
                    "sparklink: SSAP indication queue full handle=0x{:04x}\n",
                    handle
                );
            }
        }

        Ok(())
    }

    /// Write client-configuration descriptor for a property.
    pub fn set_client_config(&mut self, handle: u16, config: u16) -> Result {
        for svc in self.services.iter_mut() {
            for p in svc.properties.iter_mut() {
                if p.handle == handle {
                    if !p.ops.contains(OpIndicator::CLIENT_CFG_WR) {
                        return Err(EACCES);
                    }
                    p.client_cfg = config;
                    return Ok(());
                }
            }
        }
        Err(ENOENT)
    }

    // -----------------------------------------------------------------------
    // Notification / indication
    // -----------------------------------------------------------------------

    /// Send a server-initiated notification for a property handle.
    pub fn notify(&mut self, handle: u16) -> Result {
        let data = self.read_property(handle)?;
        self.notifications.push(
            PendingNotification {
                handle,
                indication: false,
                data,
            },
            GFP_KERNEL,
        )?;
        Ok(())
    }

    /// Send a server-initiated indication for a property handle.
    pub fn indicate(&mut self, handle: u16) -> Result {
        let data = self.read_property(handle)?;
        self.notifications.push(
            PendingNotification {
                handle,
                indication: true,
                data,
            },
            GFP_KERNEL,
        )?;
        Ok(())
    }

    /// Dequeue one pending notification/indication.
    pub fn dequeue_notification(&mut self) -> Option<PendingNotification> {
        if self.notifications.is_empty() {
            return None;
        }
        self.notifications.remove(0).ok()
    }

    /// Get the number of pending notifications.
    pub fn notification_count(&self) -> usize {
        self.notifications.len()
    }

    // -----------------------------------------------------------------------
    // Method invocation
    // -----------------------------------------------------------------------

    /// Invoke a method: store input, generate output (echo for now).
    pub fn call_method(&mut self, handle: u16, input: &[u8]) -> Result<KVec<u8>> {
        for svc in self.services.iter_mut() {
            for m in svc.methods.iter_mut() {
                if m.handle == handle {
                    m.input.clear();
                    m.input.extend_from_slice(input, GFP_KERNEL)?;
                    // Default implementation: echo input as output
                    m.output.clear();
                    m.output.extend_from_slice(input, GFP_KERNEL)?;
                    let mut out = KVec::new();
                    out.extend_from_slice(&m.output, GFP_KERNEL)?;
                    return Ok(out);
                }
            }
        }
        Err(ENOENT)
    }

    // -----------------------------------------------------------------------
    // Built-in demo service: SparkLink Device Info
    // -----------------------------------------------------------------------

    /// Register the standard SparkLink device information service.
    /// UUID 0x0001 with properties: device_name (0x1001), firmware_version (0x1002).
    pub fn register_device_info_service(&mut self) -> Result {
        let svc_uuid = SsapUuid::Uuid16(0x0001);
        self.register_service(svc_uuid, true)?;

        // Property: Device Name (readable)
        let name = b"SparkLink Virtual Device";
        self.add_property(SsapUuid::Uuid16(0x1001), OpIndicator::READ, name)?;

        // Property: Firmware Version (readable)
        let fw = b"0.3.0";
        self.add_property(SsapUuid::Uuid16(0x1002), OpIndicator::READ, fw)?;

        // Property: Status (readable, writable, notifiable)
        let status: [u8; 1] = [0x00]; // idle
        let status_handle = self.add_property(
            SsapUuid::Uuid16(0x1003),
            OpIndicator::READ
                | OpIndicator::WRITE_WITH_RSP
                | OpIndicator::NOTIFY
                | OpIndicator::CLIENT_CFG_WR,
            &status,
        )?;

        // Add format descriptor to the status property
        let format = [
            DataType::Uint8 as u8, // type
            0x00,                  // decimal exponent
            0x00,                  // binary exponent
            0x00,
            0x00, // unit UUID (none)
            0x00,
            0x00, // description UUID (none)
        ];
        self.add_descriptor(DescriptorType::PropertyFormat, &format)?;

        // Event: Status Change
        self.add_event(SsapUuid::Uuid16(0x8001))?;

        // Method: Reset device (input: none, output: status byte)
        self.add_method(SsapUuid::Uuid16(0x7001))?;

        let _ = status_handle;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Summary / debug info
    // -----------------------------------------------------------------------

    /// Get total count of registered services.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Get total property count across all services.
    pub fn property_count(&self) -> usize {
        self.services.iter().map(|s| s.properties.len()).sum()
    }

    /// Get total handle count (services + properties + methods + events).
    pub fn total_entries(&self) -> usize {
        self.services
            .iter()
            .map(|s| 1 + s.properties.len() + s.methods.len() + s.events.len())
            .sum()
    }
}

// ---------------------------------------------------------------------------
// Discovery result info
// ---------------------------------------------------------------------------

/// Simplified entry info returned from discovery queries.
#[derive(Copy, Clone, Debug)]
pub struct EntryInfo {
    pub handle: u16,
    pub category: EntryCategory,
    pub uuid: SsapUuid,
}

// ---------------------------------------------------------------------------
// SSAP PDU wire codec (T/XS 20001-2025 section 7.4.4)
//
// Each SSAP PDU has a 1-byte opcode (SsapMsgCode) followed by
// type-specific fields. All multi-byte integers are little-endian.
// ---------------------------------------------------------------------------

/// Maximum raw PDU buffer size. Bounded by the service management
/// channel MTU (default 247, negotiable up to controller max_mtu).
pub const SSAP_PDU_MAX: usize = 247;

/// Parsed SSAP PDU.
#[derive(Debug)]
pub enum SsapPdu {
    /// Error response: request opcode, error handle, error code.
    ErrorRsp {
        req_opcode: u8,
        handle: u16,
        error: SsapError,
    },
    /// Exchange info request: client MTU.
    ExchangeInfoReq { mtu: u16 },
    /// Exchange info response: server MTU.
    ExchangeInfoRsp { mtu: u16 },
    /// Find structure request: start/end handle range.
    FindStructureReq { start_handle: u16, end_handle: u16 },
    /// Find structure response: list of (handle, category, uuid) entries.
    FindStructureRsp { entries: KVec<EntryInfo> },
    /// Read request: attribute handle.
    ReadReq { handle: u16 },
    /// Read response: attribute value.
    ReadRsp { data: KVec<u8> },
    /// Write command (no response): handle + value.
    WriteCmd { handle: u16, data: KVec<u8> },
    /// Write request (with response): handle + value.
    WriteReq { handle: u16, data: KVec<u8> },
    /// Write response: handle.
    WriteRsp { handle: u16 },
    /// Value notification: handle + value.
    ValueNtf { handle: u16, data: KVec<u8> },
    /// Value indication: handle + value.
    ValueInd { handle: u16, data: KVec<u8> },
    /// Value acknowledgement: handle.
    ValueAck { handle: u16 },
}

impl SsapPdu {
    /// Encode this PDU into a byte buffer.
    /// Returns the number of bytes written, or ENOMEM/EINVAL on error.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        match self {
            SsapPdu::ErrorRsp {
                req_opcode,
                handle,
                error,
            } => {
                if buf.len() < 4 {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ErrorRsp as u8;
                buf[1] = *req_opcode;
                buf[2..4].copy_from_slice(&handle.to_le_bytes());
                buf[4] = *error as u8;
                Ok(5)
            }
            SsapPdu::ExchangeInfoReq { mtu } => {
                if buf.len() < 3 {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ExchangeInfoReq as u8;
                buf[1..3].copy_from_slice(&mtu.to_le_bytes());
                Ok(3)
            }
            SsapPdu::ExchangeInfoRsp { mtu } => {
                if buf.len() < 3 {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ExchangeInfoRsp as u8;
                buf[1..3].copy_from_slice(&mtu.to_le_bytes());
                Ok(3)
            }
            SsapPdu::FindStructureReq {
                start_handle,
                end_handle,
            } => {
                if buf.len() < 5 {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::FindStructureReq as u8;
                buf[1..3].copy_from_slice(&start_handle.to_le_bytes());
                buf[3..5].copy_from_slice(&end_handle.to_le_bytes());
                Ok(5)
            }
            SsapPdu::FindStructureRsp { entries } => {
                // Each entry: handle(2) + category(1) + uuid_len(1) + uuid(2 or 16)
                let hdr = 1;
                let needed = hdr
                    + entries
                        .iter()
                        .map(|e| {
                            4 + match e.uuid {
                                SsapUuid::Uuid16(_) => 2,
                                SsapUuid::Uuid128(_) => 16,
                            }
                        })
                        .sum::<usize>();
                if buf.len() < needed {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::FindStructureRsp as u8;
                let mut off = 1;
                for e in entries.iter() {
                    buf[off..off + 2].copy_from_slice(&e.handle.to_le_bytes());
                    buf[off + 2] = e.category as u8;
                    match e.uuid {
                        SsapUuid::Uuid16(v) => {
                            buf[off + 3] = 2;
                            buf[off + 4..off + 6].copy_from_slice(&v.to_le_bytes());
                            off += 6;
                        }
                        SsapUuid::Uuid128(v) => {
                            buf[off + 3] = 16;
                            buf[off + 4..off + 20].copy_from_slice(&v);
                            off += 20;
                        }
                    }
                }
                Ok(off)
            }
            SsapPdu::ReadReq { handle } => {
                if buf.len() < 3 {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ReadReq as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                Ok(3)
            }
            SsapPdu::ReadRsp { data } => {
                if buf.len() < 1 + data.len() {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ReadRsp as u8;
                buf[1..1 + data.len()].copy_from_slice(data);
                Ok(1 + data.len())
            }
            SsapPdu::WriteCmd { handle, data } => {
                if buf.len() < 3 + data.len() {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::WriteCmd as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..3 + data.len()].copy_from_slice(data);
                Ok(3 + data.len())
            }
            SsapPdu::WriteReq { handle, data } => {
                if buf.len() < 3 + data.len() {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::WriteReq as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..3 + data.len()].copy_from_slice(data);
                Ok(3 + data.len())
            }
            SsapPdu::WriteRsp { handle } => {
                if buf.len() < 3 {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::WriteRsp as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                Ok(3)
            }
            SsapPdu::ValueNtf { handle, data } => {
                if buf.len() < 3 + data.len() {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ValueNtf as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..3 + data.len()].copy_from_slice(data);
                Ok(3 + data.len())
            }
            SsapPdu::ValueInd { handle, data } => {
                if buf.len() < 3 + data.len() {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ValueInd as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..3 + data.len()].copy_from_slice(data);
                Ok(3 + data.len())
            }
            SsapPdu::ValueAck { handle } => {
                if buf.len() < 3 {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ValueAck as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                Ok(3)
            }
        }
    }

    /// Decode a raw byte buffer into an SSAP PDU.
    /// Returns the parsed PDU or EINVAL if malformed.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(EINVAL);
        }
        let opcode = buf[0];
        let payload = &buf[1..];
        match opcode {
            0x01 => {
                // ErrorRsp: req_opcode(1) + handle(2) + error(1) = 4
                if payload.len() < 4 {
                    return Err(EINVAL);
                }
                Ok(SsapPdu::ErrorRsp {
                    req_opcode: payload[0],
                    handle: u16::from_le_bytes([payload[1], payload[2]]),
                    error: SsapError::from_raw(payload[3]),
                })
            }
            0x02 => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                Ok(SsapPdu::ExchangeInfoReq {
                    mtu: u16::from_le_bytes([payload[0], payload[1]]),
                })
            }
            0x03 => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                Ok(SsapPdu::ExchangeInfoRsp {
                    mtu: u16::from_le_bytes([payload[0], payload[1]]),
                })
            }
            0x04 => {
                if payload.len() < 4 {
                    return Err(EINVAL);
                }
                Ok(SsapPdu::FindStructureReq {
                    start_handle: u16::from_le_bytes([payload[0], payload[1]]),
                    end_handle: u16::from_le_bytes([payload[2], payload[3]]),
                })
            }
            0x05 => {
                let mut entries = KVec::new();
                let mut off = 0;
                while off + 4 <= payload.len() {
                    let handle = u16::from_le_bytes([payload[off], payload[off + 1]]);
                    let category_raw = payload[off + 2];
                    let uuid_len = payload[off + 3] as usize;
                    off += 4;
                    if off + uuid_len > payload.len() {
                        break;
                    }
                    let uuid = if uuid_len == 2 {
                        SsapUuid::Uuid16(u16::from_le_bytes([payload[off], payload[off + 1]]))
                    } else if uuid_len == 16 {
                        let mut u = [0u8; 16];
                        u.copy_from_slice(&payload[off..off + 16]);
                        SsapUuid::Uuid128(u)
                    } else {
                        off += uuid_len;
                        continue;
                    };
                    let category = match category_raw {
                        0x00 => EntryCategory::PrimaryService,
                        0x01 => EntryCategory::SecondaryService,
                        0x02 => EntryCategory::Property,
                        0x03 => EntryCategory::Method,
                        0x04 => EntryCategory::Event,
                        0x05 => EntryCategory::ServiceRef,
                        0x08 => EntryCategory::CustomPrimaryService,
                        0x09 => EntryCategory::CustomSecondaryService,
                        0x0A => EntryCategory::CustomProperty,
                        0x0B => EntryCategory::CustomMethod,
                        0x0C => EntryCategory::CustomEvent,
                        0x0D => EntryCategory::CustomServiceRef,
                        _ => {
                            off += uuid_len;
                            continue;
                        }
                    };
                    let _ = entries.push(
                        EntryInfo {
                            handle,
                            category,
                            uuid,
                        },
                        GFP_KERNEL,
                    );
                    off += uuid_len;
                }
                Ok(SsapPdu::FindStructureRsp { entries })
            }
            0x08 => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                Ok(SsapPdu::ReadReq {
                    handle: u16::from_le_bytes([payload[0], payload[1]]),
                })
            }
            0x09 => {
                let mut data = KVec::new();
                for &b in payload {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::ReadRsp { data })
            }
            0x0C => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let mut data = KVec::new();
                for &b in &payload[2..] {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::WriteCmd { handle, data })
            }
            0x0D => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let mut data = KVec::new();
                for &b in &payload[2..] {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::WriteReq { handle, data })
            }
            0x0E => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                Ok(SsapPdu::WriteRsp {
                    handle: u16::from_le_bytes([payload[0], payload[1]]),
                })
            }
            0x0F => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let mut data = KVec::new();
                for &b in &payload[2..] {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::ValueNtf { handle, data })
            }
            0x10 => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let mut data = KVec::new();
                for &b in &payload[2..] {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::ValueInd { handle, data })
            }
            0x11 => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                Ok(SsapPdu::ValueAck {
                    handle: u16::from_le_bytes([payload[0], payload[1]]),
                })
            }
            _ => Err(EINVAL),
        }
    }
}

// ---------------------------------------------------------------------------
// SSAP session — binds SSAP to a transport channel on a connection
// ---------------------------------------------------------------------------

/// Per-connection SSAP session state.
///
/// Tracks the service management channel binding for a specific
/// connection handle. Each session negotiates MTU independently
/// and can hold a remote service discovery cache.
pub struct SsapSession {
    /// Connection handle this session is bound to.
    pub conn_handle: u16,
    /// Transport channel TCID (normally SERVICE_MGMT = 0x0A).
    pub tcid: u16,
    /// Negotiated MTU for this session.
    pub mtu: u16,
    /// Whether ExchangeInfo has completed.
    pub info_exchanged: bool,
    /// Remote service cache for this peer.
    pub remote_db: RemoteServiceDb,
}

impl SsapSession {
    /// Create a new SSAP session bound to a connection.
    pub fn new(conn_handle: u16) -> Self {
        Self {
            conn_handle,
            tcid: crate::sle_conn::tcid::SERVICE_MGMT,
            mtu: 247,
            info_exchanged: false,
            remote_db: RemoteServiceDb::new(),
        }
    }

    /// Build an ExchangeInfoReq PDU to initiate MTU negotiation.
    pub fn build_exchange_info_req(&self, local_mtu: u16, buf: &mut [u8]) -> Result<usize> {
        let pdu = SsapPdu::ExchangeInfoReq { mtu: local_mtu };
        pdu.encode(buf)
    }

    /// Process a received ExchangeInfoRsp from the peer.
    /// Updates the session MTU to the minimum of local and remote.
    pub fn handle_exchange_info_rsp(&mut self, remote_mtu: u16, local_mtu: u16) {
        self.mtu = remote_mtu.min(local_mtu);
        self.info_exchanged = true;
    }

    /// Process a received SSAP PDU and generate a response if needed.
    /// This is the server-side PDU handler.
    /// Returns the response PDU length in `resp_buf`, or 0 if no response.
    pub fn process_incoming(
        &mut self,
        ssap: &mut SsapInner,
        pdu_data: &[u8],
        resp_buf: &mut [u8],
    ) -> Result<usize> {
        let pdu = SsapPdu::decode(pdu_data)?;
        match pdu {
            SsapPdu::ExchangeInfoReq { mtu: remote_mtu } => {
                self.mtu = remote_mtu.min(self.mtu);
                self.info_exchanged = true;
                let rsp = SsapPdu::ExchangeInfoRsp { mtu: self.mtu };
                rsp.encode(resp_buf)
            }
            SsapPdu::FindStructureReq {
                start_handle,
                end_handle,
            } => {
                let entries = ssap.find_in_range(start_handle, end_handle);
                let rsp = SsapPdu::FindStructureRsp { entries };
                rsp.encode(resp_buf)
            }
            SsapPdu::ReadReq { handle } => match ssap.read_property(handle) {
                Ok(data) => {
                    let rsp = SsapPdu::ReadRsp { data };
                    rsp.encode(resp_buf)
                }
                Err(_) => {
                    let rsp = SsapPdu::ErrorRsp {
                        req_opcode: SsapMsgCode::ReadReq as u8,
                        handle,
                        error: SsapError::PropertyNotFound,
                    };
                    rsp.encode(resp_buf)
                }
            },
            SsapPdu::WriteCmd { handle, data } => {
                let _ = ssap.write_property(handle, &data);
                Ok(0) // No response for WriteCmd
            }
            SsapPdu::WriteReq { handle, data } => match ssap.write_property(handle, &data) {
                Ok(()) => {
                    let rsp = SsapPdu::WriteRsp { handle };
                    rsp.encode(resp_buf)
                }
                Err(_) => {
                    let rsp = SsapPdu::ErrorRsp {
                        req_opcode: SsapMsgCode::WriteReq as u8,
                        handle,
                        error: SsapError::WriteNotPermitted,
                    };
                    rsp.encode(resp_buf)
                }
            },
            SsapPdu::ValueAck { handle: _ } => {
                // Acknowledge received; no action needed in this minimal impl.
                Ok(0)
            }
            // Client-side responses: store in remote cache
            SsapPdu::ExchangeInfoRsp { mtu } => {
                self.handle_exchange_info_rsp(mtu, self.mtu);
                Ok(0)
            }
            SsapPdu::FindStructureRsp { entries } => {
                for e in entries.iter() {
                    let _ = self.remote_db.add_entry(*e);
                }
                Ok(0)
            }
            SsapPdu::ReadRsp { data } => {
                // In a full implementation, this would be routed to the
                // pending request via transaction ID. For now, store as
                // last-read value.
                self.remote_db.last_read_value = data;
                Ok(0)
            }
            SsapPdu::WriteRsp { handle: _ } => {
                // Write confirmed. No additional action.
                Ok(0)
            }
            _ => {
                // Unsupported PDU — send ErrorRsp
                let rsp = SsapPdu::ErrorRsp {
                    req_opcode: pdu_data[0],
                    handle: 0,
                    error: SsapError::RequestNotSupported,
                };
                rsp.encode(resp_buf)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Remote service database cache
// ---------------------------------------------------------------------------

/// Cached remote service database discovered via SSAP.
///
/// Stores the structural view of a remote peer's service database
/// obtained through FindStructure requests. This allows the local
/// host to look up remote handles without repeated over-the-air queries.
pub struct RemoteServiceDb {
    /// Discovered entries from the remote peer.
    pub entries: KVec<EntryInfo>,
    /// Whether a full discovery has been completed.
    pub discovery_complete: bool,
    /// Last-read property value (placeholder for request-response routing).
    pub last_read_value: KVec<u8>,
}

impl RemoteServiceDb {
    /// Create an empty remote service cache.
    pub fn new() -> Self {
        Self {
            entries: KVec::new(),
            discovery_complete: false,
            last_read_value: KVec::new(),
        }
    }

    /// Add a discovered entry to the cache.
    pub fn add_entry(&mut self, entry: EntryInfo) -> Result {
        // Avoid duplicates by handle.
        for existing in self.entries.iter() {
            if existing.handle == entry.handle {
                return Ok(());
            }
        }
        self.entries.push(entry, GFP_KERNEL)?;
        Ok(())
    }

    /// Find a remote service by UUID.
    pub fn find_service_by_uuid(&self, uuid: &SsapUuid) -> Option<&EntryInfo> {
        self.entries.iter().find(|e| {
            (e.category == EntryCategory::PrimaryService
                || e.category == EntryCategory::CustomPrimaryService)
                && e.uuid == *uuid
        })
    }

    /// Get all discovered primary services.
    pub fn primary_services(&self) -> impl Iterator<Item = &EntryInfo> {
        self.entries.iter().filter(|e| {
            e.category == EntryCategory::PrimaryService
                || e.category == EntryCategory::CustomPrimaryService
        })
    }

    /// Clear the cache (e.g. on disconnection).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.last_read_value.clear();
        self.discovery_complete = false;
    }

    /// Number of cached entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}
