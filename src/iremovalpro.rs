//! FFI bindings for iremovalpro.dll
//!
//! This module provides safe Rust wrappers around the native iremovalpro.dll exports:
//! - Action: Main bypass execution entry point
//! - SetCallbacks: Register callbacks for progress/status updates
//! - SetWinInfo: Set window handle/info for UI integration
//! - DotNetRuntimeDebugHeader: Debug header (internal use)

use std::ffi::{c_void, CStr, CString};
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use libc::{c_char, c_int, c_ulong, c_ushort};
use tracing::{debug, error, info, warn};

use crate::error::{Error, Result};

/// Calling convention for Windows API (stdcall on x86, fastcall on x64)
#[cfg(target_arch = "x86")]
type CallingConvention = extern "stdcall" fn();
#[cfg(target_arch = "x64")]
type CallingConvention = extern "system" fn();

/// Function pointer type for callbacks
type CallbackFn = extern "system" fn(c_int, *const c_char, *mut c_void);

/// Callback context passed to native code
#[repr(C)]
struct CallbackContext {
    user_data: *mut c_void,
    callback: CallbackFn,
}

/// WinInfo structure passed to SetWinInfo
#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

impl Default for WinInfo {
    fn default() -> Self {
        Self {
            hwnd: std::ptr::null_mut(),
            process_id: 0,
            thread_id: 0,
            reserved: [0; 4],
        }
    }
}

/// Callback types for progress reporting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CallbackType {
    /// General progress (0-100)
    Progress = 0,
    /// Status message
    Status = 1,
    /// Error occurred
    Error = 2,
    /// Stage changed
    Stage = 3,
    /// Device connected/disconnected
    DeviceChange = 4,
    /// Log message
    Log = 5,
    /// Request user input
    InputRequest = 6,
    /// Operation completed
    Complete = 7,
}

/// Safe callback handler trait
pub trait IremovalProCallback: Send + Sync {
    /// Called with progress/status updates
    fn on_callback(&self, cb_type: CallbackType, message: &str, progress: Option<u8>);
}

/// Default no-op callback implementation
pub struct NoopCallback;

impl IremovalProCallback for NoopCallback {
    fn on_callback(&self, _cb_type: CallbackType, _message: &str, _progress: Option<u8>) {}
}

/// Thread-safe callback wrapper
#[derive(Clone)]
pub struct IremovalProCallbacks {
    inner: Arc<Mutex<Option<Box<dyn IremovalProCallback>>>>,
    extern_fn: CallbackFn,
    context: *mut c_void,
}

impl Default for IremovalProCallbacks {
    fn default() -> Self {
        Self::new()
    }
}

impl IremovalProCallbacks {
    /// Create new callbacks handler
    pub fn new() -> Self {
        let inner = Arc::new(Mutex::new(None));
        let inner_clone = inner.clone();

        // Create the extern "C" callback function
        let extern_fn: CallbackFn = move |cb_type_raw, message_ptr, user_data| {
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

        // We need to store the function pointer
        let context = Box::into_raw(Box::new(())) as *mut c_void;

        Self {
            inner,
            extern_fn,
            context,
        }
    }

    /// Set the callback implementation
    pub fn set_callback<C: IremovalProCallback + 'static>(&mut self, callback: C) {
        let mut guard = self.inner.lock().unwrap();
        *guard = Some(Box::new(callback));
    }

    /// Get the raw function pointer for FFI
    pub fn as_raw(&self) -> CallbackFn {
        self.extern_fn
    }

    /// Get the context pointer
    pub fn context(&self) -> *mut c_void {
        self.context
    }
}

impl Drop for IremovalProCallbacks {
    fn drop(&mut self) {
        if !self.context.is_null() {
            unsafe {
                drop(Box::from_raw(self.context as *mut ()));
            }
        }
    }
}

/// Main wrapper for iremovalpro.dll
pub struct IremovalPro {
    /// Handle to loaded library
    library: Option<LibraryHandle>,
    /// Function pointers
    action_fn: Option<ActionFn>,
    set_callbacks_fn: Option<SetCallbacksFn>,
    set_win_info_fn: Option<SetWinInfoFn>,
    /// Library path
    path: std::path::PathBuf,
}

/// Function signature for Action
type ActionFn = unsafe extern "system" fn(
    *const c_char,  // device_udid
    *const c_char,  // operation_type
    *const c_char,  // params_json
    *mut c_char,    // output_buffer
    c_int,          // output_buffer_size
) -> c_int;

/// Function signature for SetCallbacks
type SetCallbacksFn = unsafe extern "system" fn(
    CallbackFn,     // callback function
    *mut c_void,    // user data
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
            let proc = unsafe { winapi::um::libloaderapi::GetProcAddress(self.handle, c_name.as_ptr()) };
            if proc.is_null() {
                return Err(Error::function_not_found(name.to_string(), "iremovalpro.dll"));
            }
            Ok(proc as *mut c_void)
        }
        #[cfg(not(windows))]
        {
            let c_name = CString::new(name)?;
            let sym = unsafe { libc::dlsym(self.handle, c_name.as_ptr()) };
            if sym.is_null() {
                return Err(Error::function_not_found(name.to_string(), "iremovalpro.dll"));
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

impl IremovalPro {
    /// Create new IremovalPro instance
    ///
    /// # Arguments
    /// * `dll_path` - Path to iremovalpro.dll (if None, searches in default locations)
    pub fn new(dll_path: Option<impl AsRef<Path>>) -> Result<Self> {
        let path = if let Some(p) = dll_path {
            p.as_ref().to_path_buf()
        } else {
            Self::find_dll()?
        };

        info!("Loading iremovalpro.dll from: {}", path.display());

        let library = LibraryHandle::new(&path)?;

        // Load function pointers
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

        Ok(Self {
            library: Some(library),
            action_fn: Some(action_fn),
            set_callbacks_fn: Some(set_callbacks_fn),
            set_win_info_fn: Some(set_win_info_fn),
            path,
        })
    }

    /// Find iremovalpro.dll in common locations
    fn find_dll() -> Result<std::path::PathBuf> {
        let search_paths = [
            // Current directory
            std::env::current_dir()?.join("iremovalpro.dll"),
            // Same directory as executable
            std::env::current_exe()?
                .parent()
                .unwrap_or(&std::path::PathBuf::new())
                .join("iremovalpro.dll"),
            // BFF tool directory
            std::path::PathBuf::from(r"C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\iremovalpro.dll"),
            // System paths
            std::path::PathBuf::from(r"C:\Windows\System32\iremovalpro.dll"),
        ];

        for path in &search_paths {
            if path.exists() {
                return Ok(path.clone());
            }
        }

        Err(Error::native_library(
            "iremovalpro.dll not found. Please specify path explicitly or place in working directory.",
        ))
    }

    /// Set callbacks for progress/status updates
    pub fn set_callbacks(&self, callbacks: &IremovalProCallbacks) -> Result<i32> {
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

    /// Execute the main bypass action
    ///
    /// # Arguments
    /// * `device_udid` - Target device UDID (empty for auto-detect)
    /// * `operation` - Operation type: "bypass", "info", "backup", "restore"
    /// * `params` - JSON parameters for the operation
    ///
    /// # Returns
    /// JSON result string from the operation
    pub fn action(
        &self,
        device_udid: &str,
        operation: &str,
        params: &str,
    ) -> Result<String> {
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
        let len = output_buffer.iter().position(|&c| c == 0).unwrap_or(BUFFER_SIZE);
        let output = String::from_utf8_lossy(
            &output_buffer[..len]
                .iter()
                .map(|&c| c as u8)
                .collect::<Vec<u8>>(),
        )
        .into_owned();

        Ok(output)
    }

    /// Execute action with typed parameters
    pub fn action_typed<P: serde::Serialize, R: for<'de> serde::Deserialize<'de>>(
        &self,
        device_udid: &str,
        operation: &str,
        params: &P,
    ) -> Result<R> {
        let params_json = serde_json::to_string(params)?;
        let result_json = self.action(device_udid, operation, &params_json)?;
        let result: R = serde_json::from_str(&result_json)?;
        Ok(result)
    }

    /// Get library path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Builder for IremovalPro
pub struct IremovalProBuilder {
    dll_path: Option<std::path::PathBuf>,
    callbacks: Option<IremovalProCallbacks>,
    win_info: Option<WinInfo>,
}

impl IremovalProBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            dll_path: None,
            callbacks: None,
            win_info: None,
        }
    }

    /// Set DLL path
    pub fn dll_path(mut self, path: impl AsRef<Path>) -> Self {
        self.dll_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set callbacks
    pub fn callbacks(mut self, callbacks: IremovalProCallbacks) -> Self {
        self.callbacks = Some(callbacks);
        self
    }

    /// Set window info
    pub fn win_info(mut self, win_info: WinInfo) -> Self {
        self.win_info = Some(win_info);
        self
    }

    /// Build and initialize
    pub fn build(self) -> Result<IremovalPro> {
        let iremoval = IremovalPro::new(self.dll_path)?;

        if let Some(cb) = self.callbacks {
            iremoval.set_callbacks(&cb)?;
        }

        if let Some(wi) = self.win_info {
            iremoval.set_win_info(&wi)?;
        }

        Ok(iremoval)
    }
}

impl Default for IremovalProBuilder {
    fn default() -> Self {
        Self::new()
    }
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
}