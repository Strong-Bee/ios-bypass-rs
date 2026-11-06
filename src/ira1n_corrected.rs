//! Corrected FFI bindings for ira1n.dll based on REA reverse engineering
//!
//! This module provides the ACTUAL function signatures discovered through
//! static analysis of the native DLL exports. The original ira1n.rs had
//! incorrect function names (IRa1n_Init, IRa1n_Execute, IRa1n_Cleanup).
//!
//! Actual exports from ira1n.dll (internally checkra1n.dll):
//! - Action (ordinal 1) - Main bypass entry point
//! - DotNetRuntimeDebugHeader (ordinal 2) - Debug header
//! - SetCallbacks (ordinal 3) - Register callbacks
//! - SetWinInfo (ordinal 4) - Set window info

use std::ffi::{c_void, CStr, CString};
use std::mem;
use std::path::Path;
use std::sync::{Arc, Mutex};

use libc::{c_char, c_int, c_ulong};
use tracing::{debug, info, warn};

use crate::error::{Error, Result};

/// Calling convention for Windows x64 (system = fastcall)
#[cfg(target_arch = "x86_64")]
type CallingConvention = extern "system" fn();
#[cfg(target_arch = "x86")]
type CallingConvention = extern "stdcall" fn();

/// Callback function type matching the native signature
type NativeCallbackFn = extern "system" fn(c_int, *const c_char, *mut c_void);

/// WinInfo structure matching the native layout (from iremovalpro.dll analysis)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WinInfo {
    /// Window handle (HWND)
    pub hwnd: *mut c_void,
    /// Process ID
    pub process_id: c_ulong,
    /// Thread ID
    pub thread_id: c_ulong,
    /// Reserved for future use
    pub reserved: [c_ulong; 4],
}

impl WinInfo {
    /// Create WinInfo for current process/thread
    pub fn for_current_thread(hwnd: *mut c_void) -> Self {
        Self {
            hwnd,
            process_id: std::process::id(),
            thread_id: unsafe { libc::pthread_self() as c_ulong },
            reserved: [0; 4],
        }
    }
}

/// Callback types matching the native enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CallbackType {
    Progress = 0,
    Status = 1,
    Error = 2,
    Stage = 3,
    DeviceChange = 4,
    Log = 5,
    InputRequest = 6,
    Complete = 7,
}

/// Safe callback handler trait
pub trait Ira1nCallback: Send + Sync {
    fn on_callback(&self, cb_type: CallbackType, message: &str, progress: Option<u8>);
}

/// Default no-op callback
pub struct NoopCallback;
impl Ira1nCallback for NoopCallback {
    fn on_callback(&self, _cb_type: CallbackType, _message: &str, _progress: Option<u8>) {}
}

/// Thread-safe callback wrapper
#[derive(Clone)]
pub struct Ira1nCallbacks {
    inner: Arc<Mutex<Option<Box<dyn Ira1nCallback>>>>,
    extern_fn: NativeCallbackFn,
    context: *mut c_void,
}

impl Default for Ira1nCallbacks {
    fn default() -> Self {
        Self::new()
    }
}

impl Ira1nCallbacks {
    pub fn new() -> Self {
        let inner = Arc::new(Mutex::new(None));
        let inner_clone = inner.clone();

        // Create the extern "C" callback function
        let extern_fn: NativeCallbackFn = move |cb_type_raw, message_ptr, user_data| {
            let cb_type = match cb_type_raw {
                0 => CallbackType::Progress,
                1 => CallbackType::Status,
                2 => CallbackType::Error,
                3 => CallbackType::Stage,
                4 => CallbackType::DeviceChange,
                5 => CallbackType::Log,
                6 => CallbackType::InputRequest,
                7 => CallbackType::Complete,
                _ => return,
            };

            let message = unsafe {
                if message_ptr.is_null() {
                    String::new()
                } else {
                    CStr::from_ptr(message_ptr).to_string_lossy().into_owned()
                }
            };

            let progress = if cb_type == CallbackType::Progress {
                Some(message.parse().unwrap_or(0))
            } else {
                None
            };

            // Call the Rust callback
            if let Ok(mut guard) = inner_clone.lock() {
                if let Some(cb) = guard.as_mut() {
                    cb.on_callback(cb_type, &message, progress);
                }
            }
        };

        let context = Box::into_raw(Box::new(())) as *mut c_void;

        Self {
            inner,
            extern_fn,
            context,
        }
    }

    pub fn set_callback<C: Ira1nCallback + 'static>(&mut self, callback: C) {
        let mut guard = self.inner.lock().unwrap();
        *guard = Some(Box::new(callback));
    }

    pub fn as_raw(&self) -> NativeCallbackFn {
        self.extern_fn
    }

    pub fn context(&self) -> *mut c_void {
        self.context
    }
}

impl Drop for Ira1nCallbacks {
    fn drop(&mut self) {
        if !self.context.is_null() {
            unsafe {
                drop(Box::from_raw(self.context as *mut ()));
            }
        }
    }
}

/// Main wrapper for ira1n.dll (checkra1n.dll)
pub struct IRa1nNative {
    library: Option<LibraryHandle>,
    action_fn: Option<ActionFn>,
    set_callbacks_fn: Option<SetCallbacksFn>,
    set_win_info_fn: Option<SetWinInfoFn>,
    path: std::path::PathBuf,
}

/// Function signature for Action (THE MAIN ENTRY POINT)
///
/// Parameters:
/// - device_udid: Target device UDID (empty for auto-detect)
/// - operation: Operation type ("bypass", "info", "exploit", "backup", "restore")
/// - params_json: JSON parameters for the operation
/// - output_buffer: Buffer to receive JSON result
/// - output_buffer_size: Size of output buffer
///
/// Returns: 0 on success, negative error code on failure
type ActionFn = unsafe extern "system" fn(
    *const c_char, // device_udid
    *const c_char, // operation
    *const c_char, // params_json
    *mut c_char,   // output_buffer
    c_int,         // output_buffer_size
) -> c_int;

/// Function signature for SetCallbacks
type SetCallbacksFn = unsafe extern "system" fn(
    NativeCallbackFn, // callback function
    *mut c_void,      // user data
) -> c_int;

/// Function signature for SetWinInfo
type SetWinInfoFn = unsafe extern "system" fn(
    *const WinInfo, // win info struct
) -> c_int;

/// RAII wrapper for loaded library
struct LibraryHandle {
    handle: *mut c_void,
}

impl LibraryHandle {
    fn new(path: &Path) -> Result<Self> {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let handle = unsafe { winapi::um::libloaderapi::LoadLibraryW(wide_path.as_ptr()) };
            if handle.is_null() {
                let err = std::io::Error::last_os_error();
                return Err(Error::native_library(format!(
                    "Failed to load {}: {}",
                    path.display(),
                    err
                )));
            }
            Ok(Self { handle })
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::ffi::OsStrExt;
            let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
            let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_LAZY) };
            if handle.is_null() {
                let err = unsafe { libc::dlerror() };
                let msg = if err.is_null() {
                    "Unknown error".to_string()
                } else {
                    unsafe { CStr::from_ptr(err).to_string_lossy().into_owned() }
                };
                return Err(Error::native_library(format!(
                    "Failed to load {}: {}",
                    path.display(),
                    msg
                )));
            }
            Ok(Self { handle })
        }
    }

    fn get_symbol(&self, name: &str) -> Result<*mut c_void> {
        #[cfg(windows)]
        {
            let c_name = CString::new(name)?;
            let proc =
                unsafe { winapi::um::libloaderapi::GetProcAddress(self.handle, c_name.as_ptr()) };
            if proc.is_null() {
                return Err(Error::function_not_found(name.to_string(), "ira1n.dll"));
            }
            Ok(proc as *mut c_void)
        }
        #[cfg(not(windows))]
        {
            let c_name = CString::new(name)?;
            let sym = unsafe { libc::dlsym(self.handle, c_name.as_ptr()) };
            if sym.is_null() {
                return Err(Error::function_not_found(name.to_string(), "ira1n.dll"));
            }
            Ok(sym)
        }
    }
}

impl Drop for LibraryHandle {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            winapi::um::libloaderapi::FreeLibrary(self.handle);
        }
        #[cfg(not(windows))]
        unsafe {
            libc::dlclose(self.handle);
        }
    }
}

unsafe impl Send for LibraryHandle {}
unsafe impl Sync for LibraryHandle {}

impl IRa1nNative {
    /// Create new IRa1nNative instance with corrected function bindings
    ///
    /// # Arguments
    /// * `dll_path` - Path to ira1n.dll (if None, searches in default locations)
    pub fn new(dll_path: Option<impl AsRef<Path>>) -> Result<Self> {
        let path = if let Some(p) = dll_path {
            p.as_ref().to_path_buf()
        } else {
            Self::find_dll()?
        };

        info!("Loading ira1n.dll (checkra1n.dll) from: {}", path.display());

        let library = LibraryHandle::new(&path)?;

        // Load ACTUAL exports discovered via REA analysis
        let action_fn = unsafe {
            let sym = library.get_symbol("Action")?;
            mem::transmute::<*mut c_void, ActionFn>(sym)
        };

        let set_callbacks_fn = unsafe {
            let sym = library.get_symbol("SetCallbacks")?;
            mem::transmute::<*mut c_void, SetCallbacksFn>(sym)
        };

        let set_win_info_fn = unsafe {
            let sym = library.get_symbol("SetWinInfo")?;
            mem::transmute::<*mut c_void, SetWinInfoFn>(sym)
        };

        // Note: DotNetRuntimeDebugHeader is internal, not typically called

        Ok(Self {
            library: Some(library),
            action_fn: Some(action_fn),
            set_callbacks_fn: Some(set_callbacks_fn),
            set_win_info_fn: Some(set_win_info_fn),
            path,
        })
    }

    /// Find ira1n.dll in common locations
    fn find_dll() -> Result<std::path::PathBuf> {
        let search_paths = [
            std::env::current_dir()?.join("ira1n.dll"),
            std::env::current_exe()?
                .parent()
                .unwrap_or(&std::path::PathBuf::new())
                .join("ira1n.dll"),
            std::path::PathBuf::from(
                r"C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\ref\ira1n\ira1n.dll",
            ),
            std::path::PathBuf::from(r"C:\Windows\System32\ira1n.dll"),
        ];

        for path in &search_paths {
            if path.exists() {
                return Ok(path.clone());
            }
        }

        Err(Error::native_library(
            "ira1n.dll not found. Please specify path explicitly or place in working directory.",
        ))
    }

    /// Set callbacks for progress/status updates
    pub fn set_callbacks(&self, callbacks: &Ira1nCallbacks) -> Result<i32> {
        let fn_ptr = self
            .set_callbacks_fn
            .ok_or_else(|| Error::native_library("SetCallbacks not loaded"))?;

        let result = unsafe { fn_ptr(callbacks.as_raw(), callbacks.context()) };

        if result < 0 {
            return Err(Error::native_library(format!(
                "SetCallbacks failed with code: {}",
                result
            )));
        }

        Ok(result)
    }

    /// Set window info for UI integration
    pub fn set_win_info(&self, win_info: &WinInfo) -> Result<i32> {
        let fn_ptr = self
            .set_win_info_fn
            .ok_or_else(|| Error::native_library("SetWinInfo not loaded"))?;

        let result = unsafe { fn_ptr(win_info) };

        if result < 0 {
            return Err(Error::native_library(format!(
                "SetWinInfo failed with code: {}",
                result
            )));
        }

        Ok(result)
    }

    /// Execute the main bypass action (corrected signature matching REA findings)
    ///
    /// # Arguments
    /// * `device_udid` - Target device UDID (empty for auto-detect)
    /// * `operation` - Operation type: "bypass", "info", "exploit", "backup", "restore"
    /// * `params` - JSON parameters for the operation
    ///
    /// # Returns
    /// Parsed JSON result from the operation
    pub fn action<R: for<'de> serde::Deserialize<'de>>(
        &self,
        device_udid: &str,
        operation: &str,
        params: &str,
    ) -> Result<R> {
        let fn_ptr = self
            .action_fn
            .ok_or_else(|| Error::native_library("Action not loaded"))?;

        let device_udid_c = CString::new(device_udid)?;
        let operation_c = CString::new(operation)?;
        let params_c = CString::new(params)?;

        // Allocate output buffer (64KB)
        const BUFFER_SIZE: usize = 65536;
        let mut output_buffer = vec![0i8; BUFFER_SIZE];

        let result = unsafe {
            fn_ptr(
                device_udid_c.as_ptr(),
                operation_c.as_ptr(),
                params_c.as_ptr(),
                output_buffer.as_mut_ptr(),
                BUFFER_SIZE as c_int,
            )
        };

        if result < 0 {
            return Err(Error::bypass_failed(
                operation,
                format!("Action returned error code: {}", result),
            ));
        }

        // Find null terminator
        let len = output_buffer
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(BUFFER_SIZE);
        let output = String::from_utf8_lossy(
            &output_buffer[..len]
                .iter()
                .map(|&c| c as u8)
                .collect::<Vec<u8>>(),
        )
        .into_owned();

        let result: R = serde_json::from_str(&output)?;
        Ok(result)
    }

    /// Execute action with typed parameters (convenience method)
    pub fn action_typed<P: serde::Serialize, R: for<'de> serde::Deserialize<'de>>(
        &self,
        device_udid: &str,
        operation: &str,
        params: &P,
    ) -> Result<R> {
        let params_json = serde_json::to_string(params)?;
        self.action(device_udid, operation, &params_json)
    }

    /// Get library path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Builder for IRa1nNative
pub struct IRa1nNativeBuilder {
    dll_path: Option<std::path::PathBuf>,
    callbacks: Option<Ira1nCallbacks>,
    win_info: Option<WinInfo>,
}

impl IRa1nNativeBuilder {
    pub fn new() -> Self {
        Self {
            dll_path: None,
            callbacks: None,
            win_info: None,
        }
    }

    pub fn dll_path(mut self, path: impl AsRef<Path>) -> Self {
        self.dll_path = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn callbacks(mut self, callbacks: Ira1nCallbacks) -> Self {
        self.callbacks = Some(callbacks);
        self
    }

    pub fn win_info(mut self, win_info: WinInfo) -> Self {
        self.win_info = Some(win_info);
        self
    }

    pub fn build(self) -> Result<IRa1nNative> {
        let ira1n = IRa1nNative::new(self.dll_path)?;

        if let Some(cb) = self.callbacks {
            ira1n.set_callbacks(&cb)?;
        }

        if let Some(wi) = self.win_info {
            ira1n.set_win_info(&wi)?;
        }

        Ok(ira1n)
    }
}

impl Default for IRa1nNativeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Operation types supported by the Action function
pub mod operations {
    pub const BYPASS: &str = "bypass";
    pub const INFO: &str = "info";
    pub const EXPLOIT: &str = "exploit";
    pub const BACKUP: &str = "backup";
    pub const RESTORE: &str = "restore";
    pub const ENTER_RECOVERY: &str = "enter_recovery";
    pub const EXIT_RECOVERY: &str = "exit_recovery";
    pub const ENTER_DFU: &str = "enter_dfu";
}

/// Bypass types for the "bypass" operation
pub mod bypass_types {
    pub const ICLOUD: &str = "icloud";
    pub const PASSCODE: &str = "passcode";
    pub const MDM: &str = "mdm";
    pub const FILE_ACCESS: &str = "fileaccess";
    pub const ALL: &str = "all";
}

/// Parameters for bypass operation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BypassParams {
    pub bypass_type: String,
    pub device_udid: Option<String>,
    pub skip_backup: bool,
    pub custom_ramdisk: Option<String>,
    pub target_ios_version: Option<String>,
}

/// Result from Action function
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionResult {
    pub success: bool,
    pub message: String,
    pub device_info: Option<crate::device::DeviceInfo>,
    pub backup_path: Option<String>,
    pub logs: Vec<String>,
    pub extracted_files: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_win_info_default() {
        let wi = WinInfo::default();
        assert!(wi.hwnd.is_null());
        assert_eq!(wi.process_id, 0);
    }

    #[test]
    fn test_callback_type_values() {
        assert_eq!(CallbackType::Progress as i32, 0);
        assert_eq!(CallbackType::Complete as i32, 7);
    }

    #[test]
    fn test_bypass_params_serialization() {
        let params = BypassParams {
            bypass_type: "icloud".to_string(),
            device_udid: Some("test_udid".to_string()),
            skip_backup: false,
            custom_ramdisk: None,
            target_ios_version: Some("15.0".to_string()),
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains("icloud"));
    }
}
