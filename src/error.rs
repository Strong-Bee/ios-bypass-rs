//! Error types for iOS bypass toolkit

use std::fmt;
use thiserror::Error;

/// Main error type for the library
#[derive(Error, Debug)]
pub enum Error {
    /// FFI / native library loading error
    #[error("Native library error: {0}")]
    NativeLibrary(String),

    /// Function not found in native library
    #[error("Function not found: {function} in {library}")]
    FunctionNotFound { function: String, library: String },

    /// Invalid parameter passed to native function
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Device not found or not connected
    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    /// Device communication error
    #[error("Device communication error: {0}")]
    DeviceCommunication(String),

    /// Device in wrong state for operation
    #[error("Invalid device state: expected {expected}, got {actual}")]
    InvalidDeviceState { expected: String, actual: String },

    /// Exploit execution failed
    #[error("Exploit failed: {stage} - {reason}")]
    ExploitFailed { stage: String, reason: String },

    /// Ramdisk creation/boot failed
    #[error("Ramdisk error: {0}")]
    RamdiskError(String),

    /// Bypass operation failed
    #[error("Bypass failed: {bypass_type} - {reason}")]
    BypassFailed { bypass_type: String, reason: String },

    /// File operation failed
    #[error("File operation failed: {operation} - {path} - {reason}")]
    FileOperation { operation: String, path: String, reason: String },

    /// Cryptographic operation failed
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Timeout waiting for device/operation
    #[error("Timeout after {seconds}s: {context}")]
    Timeout { seconds: u64, context: String },

    /// Permission denied (e.g., need admin/root)
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Unsupported device/operation
    #[error("Unsupported: {0}")]
    Unsupported(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// UTF-8 conversion error
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// String conversion error
    #[error("String conversion error: {0}")]
    StringConversion(String),

    /// Generic error with context
    #[error("{context}: {source}")]
    Context { context: String, source: Box<Error> },

    /// Unknown error
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl Error {
    /// Create a new context error
    pub fn context<E: Into<Error>>(context: impl Into<String>, source: E) -> Self {
        Self::Context {
            context: context.into(),
            source: Box::new(source.into()),
        }
    }

    /// Create a new native library error
    pub fn native_library(msg: impl Into<String>) -> Self {
        Self::NativeLibrary(msg.into())
    }

    /// Create a new function not found error
    pub fn function_not_found(function: impl Into<String>, library: impl Into<String>) -> Self {
        Self::FunctionNotFound {
            function: function.into(),
            library: library.into(),
        }
    }

    /// Create a new device not found error
    pub fn device_not_found(msg: impl Into<String>) -> Self {
        Self::DeviceNotFound(msg.into())
    }

    /// Create a new exploit failed error
    pub fn exploit_failed(stage: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::ExploitFailed {
            stage: stage.into(),
            reason: reason.into(),
        }
    }

    /// Create a new bypass failed error
    pub fn bypass_failed(bypass_type: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::BypassFailed {
            bypass_type: bypass_type.into(),
            reason: reason.into(),
        }
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;

/// Extension trait for adding context to results
pub trait ResultExt<T> {
    /// Add context to an error
    fn context(self, context: impl Into<String>) -> Result<T>;

    /// Add context with a closure (evaluated only on error)
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String;
}

impl<T, E: Into<Error>> ResultExt<T> for std::result::Result<T, E> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|e| Error::context(context, e))
    }

    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| Error::context(f(), e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = Error::native_library("Failed to load iremovalpro.dll");
        assert!(err.to_string().contains("Native library error"));
    }

    #[test]
    fn test_error_context() {
        let err = Error::device_not_found("No iPhone connected")
            .context("During device enumeration");
        assert!(err.to_string().contains("During device enumeration"));
        assert!(err.to_string().contains("No iPhone connected"));
    }
}