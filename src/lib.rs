//! iOS Bypass Toolkit in Rust
//!
//! Provides safe Rust bindings for iRemoval PRO and iRa1n native libraries,
//! plus high-level APIs for iCloud bypass, Passcode bypass, MDM removal, and File Access.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(clippy::missing_safety_doc)]

pub mod error;
pub mod iremovalpro;
pub mod ira1n;
pub mod ira1n_corrected;
pub mod device;
pub mod bypass;
pub mod ramdisk;
pub mod cli;

pub use error::{Error, Result};
pub use iremovalpro::{IremovalPro, IremovalProCallbacks, WinInfo};
pub use ira1n::{IRa1n, IRa1nConfig, IRa1nBypassType, IRa1nMode, IRa1nResult, DeviceInfo as IRa1nDeviceInfo, AvailabilityReport};
pub use ira1n_corrected::{IRa1nNative, IRa1nCallbacks, WinInfo as Ira1nWinInfo, BypassParams, ActionResult, operations, bypass_types};
pub use device::{Device, DeviceInfo, DeviceState, ConnectionType, BypassType as DeviceBypassType};
pub use bypass::{BypassType, BypassConfig, BypassResult, BypassOrchestrator, BypassProgress, BypassStage};
pub use ramdisk::{RamdiskBuilder, RamdiskConfig, CompressionType, RamdiskManager};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default timeout for device operations (seconds)
pub const DEFAULT_TIMEOUT: u64 = 30;

/// Re-export commonly used types
pub mod prelude {
    pub use crate::error::{Error, Result};
    pub use crate::iremovalpro::{IremovalPro, IremovalProCallbacks, WinInfo};
    pub use crate::ira1n::{IRa1n, IRa1nConfig, IRa1nBypassType, IRa1nMode};
    pub use crate::ira1n_corrected::{IRa1nNative, IRa1nCallbacks, WinInfo as Ira1nWinInfo, BypassParams, ActionResult, operations, bypass_types};
    pub use crate::device::{Device, DeviceInfo, DeviceState, ConnectionType, BypassType as DeviceBypassType};
    pub use crate::bypass::{BypassType, BypassConfig, BypassResult, BypassOrchestrator};
    pub use crate::ramdisk::{RamdiskBuilder, RamdiskConfig};
}