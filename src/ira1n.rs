//! FFI bindings and wrapper for iRa1n (checkra1n-based) components
//!
//! iRa1n uses the checkm8 bootrom exploit (A5-A11 devices) to achieve
//! persistent code execution and enable bypass operations.

use std::ffi::{c_void, CStr, CString};
use std::mem;
use std::path::Path;
use std::sync::{Arc, Mutex};

use libc::{c_char, c_int, c_ulong};
use tracing::{debug, info, warn};

use crate::error::{Error, Result};

/// IRa1n configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IRa1nConfig {
    /// Path to ira1n.dll
    pub dll_path: Option<String>,
    /// Path to iRa1n.exe
    pub exe_path: Option<String>,
    /// Path to Data.dll
    pub data_dll_path: Option<String>,
    /// Path to libimobiledevice stack binaries
    pub libimobiledevice_dir: Option<String>,
    /// Verbose output
    pub verbose: bool,
    /// Skip backup
    pub skip_backup: bool,
    /// Custom ramdisk path
    pub custom_ramdisk: Option<String>,
    /// Target iOS version (for ramdisk selection)
    pub target_ios_version: Option<String>,
    /// Device UDID filter
    pub device_udid: Option<String>,
}

impl Default for IRa1nConfig {
    fn default() -> Self {
        Self {
            dll_path: None,
            exe_path: None,
            data_dll_path: None,
            libimobiledevice_dir: None,
            verbose: false,
            skip_backup: false,
            custom_ramdisk: None,
            target_ios_version: None,
            device_udid: None,
        }
    }
}

/// iRa1n operation modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(i32)]
pub enum IRa1nMode {
    /// Checkra1n exploit only (enter DFU, run exploit)
    ExploitOnly = 0,
    /// Full bypass with ramdisk boot
    FullBypass = 1,
    /// Enter recovery mode
    EnterRecovery = 2,
    /// Exit recovery mode
    ExitRecovery = 3,
    /// Backup device data
    Backup = 4,
    /// Restore device data
    Restore = 5,
    /// Get device info
    Info = 6,
}

/// iRa1n bypass types
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(i32)]
pub enum IRa1nBypassType {
    /// iCloud Activation Lock bypass
    iCloud = 0,
    /// Passcode bypass
    Passcode = 1,
    /// MDM removal
    MDM = 2,
    /// File system access (AFC/SSH)
    FileAccess = 3,
    /// All of the above
    All = 4,
}

/// Device state during iRa1n operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(i32)]
pub enum IRa1nDeviceState {
    Unknown = 0,
    Normal = 1,
    Recovery = 2,
    DFU = 3,
    Exploited = 4,
    RamdiskBooted = 5,
    BypassComplete = 6,
    Error = 255,
}

/// Result from iRa1n operation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IRa1nResult {
    pub success: bool,
    pub mode: IRa1nMode,
    pub bypass_type: Option<IRa1nBypassType>,
    pub device_state: IRa1nDeviceState,
    pub message: String,
    pub device_info: Option<DeviceInfo>,
    pub backup_path: Option<String>,
    pub logs: Vec<String>,
}

/// Device information from iRa1n
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceInfo {
    pub udid: String,
    pub name: Option<String>,
    pub model: String,
    pub model_id: String,
    pub ios_version: String,
    pub build_version: Option<String>,
    pub serial_number: Option<String>,
    pub imei: Option<String>,
    pub ecid: Option<String>,
    pub wifi_address: Option<String>,
    pub bluetooth_address: Option<String>,
    pub is_supervised: bool,
    pub activation_state: String,
    pub passcode_enabled: bool,
    pub mdm_locked: bool,
    pub icloud_locked: bool,
}

/// Function pointer types for ira1n.dll exports (if available)
type Ira1nInitFn = unsafe extern "system" fn(*const c_char) -> c_int;
type Ira1nExecuteFn = unsafe extern "system" fn(c_int, *const c_char, *mut c_char, c_int) -> c_int;
type Ira1nCleanupFn = unsafe extern "system" fn() -> c_int;

/// RAII wrapper for loaded ira1n.dll
struct Ira1nLibrary {
    handle: *mut c_void,
    init_fn: Option<Ira1nInitFn>,
    execute_fn: Option<Ira1nExecuteFn>,
    cleanup_fn: Option<Ira1nCleanupFn>,
}

impl Ira1nLibrary {
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

            let mut lib = Self {
                handle,
                init_fn: None,
                execute_fn: None,
                cleanup_fn: None,
            };

            // Try to load known exports
            unsafe {
                if let Ok(sym) = Self::get_symbol(handle, "IRa1n_Init") {
                    lib.init_fn = Some(mem::transmute(sym));
                }
                if let Ok(sym) = Self::get_symbol(handle, "IRa1n_Execute") {
                    lib.execute_fn = Some(mem::transmute(sym));
                }
                if let Ok(sym) = Self::get_symbol(handle, "IRa1n_Cleanup") {
                    lib.cleanup_fn = Some(mem::transmute(sym));
                }
            }

            Ok(lib)
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

            let mut lib = Self {
                handle,
                init_fn: None,
                execute_fn: None,
                cleanup_fn: None,
            };

            unsafe {
                if let Ok(sym) = Self::get_symbol(handle, "IRa1n_Init") {
                    lib.init_fn = Some(mem::transmute(sym));
                }
                if let Ok(sym) = Self::get_symbol(handle, "IRa1n_Execute") {
                    lib.execute_fn = Some(mem::transmute(sym));
                }
                if let Ok(sym) = Self::get_symbol(handle, "IRa1n_Cleanup") {
                    lib.cleanup_fn = Some(mem::transmute(sym));
                }
            }

            Ok(lib)
        }
    }

    #[cfg(windows)]
    fn get_symbol(handle: *mut c_void, name: &str) -> Result<*mut c_void> {
        let c_name = CString::new(name)?;
        let proc = unsafe { winapi::um::libloaderapi::GetProcAddress(handle, c_name.as_ptr()) };
        if proc.is_null() {
            return Err(Error::function_not_found(name.to_string(), "ira1n.dll"));
        }
        Ok(proc as *mut c_void)
    }

    #[cfg(not(windows))]
    fn get_symbol(handle: *mut c_void, name: &str) -> Result<*mut c_void> {
        let c_name = CString::new(name)?;
        let sym = unsafe { libc::dlsym(handle, c_name.as_ptr()) };
        if sym.is_null() {
            return Err(Error::function_not_found(name.to_string(), "ira1n.dll"));
        }
        Ok(sym)
    }
}

impl Drop for Ira1nLibrary {
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

/// Main iRa1n wrapper
pub struct IRa1n {
    config: IRa1nConfig,
    library: Option<Ira1nLibrary>,
    /// Process handle for iRa1n.exe
    process: Option<std::process::Child>,
    /// Callback for progress updates
    callback: Option<Arc<Mutex<Box<dyn Fn(IRa1nProgress) + Send + Sync>>>>,
}

/// Progress callback from iRa1n operations
#[derive(Debug, Clone)]
pub struct IRa1nProgress {
    pub stage: String,
    pub progress: u8, // 0-100
    pub message: String,
    pub device_state: IRa1nDeviceState,
}

impl IRa1n {
    /// Create new iRa1n instance
    pub fn new(config: IRa1nConfig) -> Result<Self> {
        let library = if let Some(dll_path) = &config.dll_path {
            let path = Path::new(dll_path);
            if path.exists() {
                info!("Loading ira1n.dll from: {}", path.display());
                Some(Ira1nLibrary::new(path)?)
            } else {
                warn!("ira1n.dll not found at: {}", path.display());
                None
            }
        } else {
            Self::find_ira1n_dll().ok().map(|p| Ira1nLibrary::new(&p)).transpose()?
        };

        Ok(Self {
            config,
            library,
            process: None,
            callback: None,
        })
    }

    /// Find ira1n.dll in common locations
    fn find_ira1n_dll() -> Result<std::path::PathBuf> {
        let search_paths = [
            std::env::current_dir()?.join("ira1n.dll"),
            std::env::current_exe()?
                .parent()
                .unwrap_or(&std::path::PathBuf::new())
                .join("ira1n.dll"),
            std::path::PathBuf::from(r"C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\ref\ira1n\ira1n.dll"),
            std::path::PathBuf::from(r"C:\Windows\System32\ira1n.dll"),
        ];

        for path in &search_paths {
            if path.exists() {
                return Ok(path.clone());
            }
        }

        Err(Error::native_library(
            "ira1n.dll not found. Please specify path explicitly.",
        ))
    }

    /// Set progress callback
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: Fn(IRa1nProgress) + Send + Sync + 'static,
    {
        self.callback = Some(Arc::new(Mutex::new(Box::new(callback))));
    }

    /// Execute iRa1n operation via DLL (if available)
    pub fn execute_dll(&self, mode: IRa1nMode, params: &str) -> Result<IRa1nResult> {
        let lib = self
            .library
            .as_ref()
            .ok_or_else(|| Error::native_library("ira1n.dll not loaded"))?;

        let execute_fn = lib
            .execute_fn
            .ok_or_else(|| Error::function_not_found("IRa1n_Execute", "ira1n.dll"))?;

        let mode_c = CString::new(mode as i32)?;
        let params_c = CString::new(params)?;

        const BUFFER_SIZE: usize = 65536;
        let mut output_buffer = vec![0i8; BUFFER_SIZE];

        let result = unsafe {
            execute_fn(
                mode as c_int,
                params_c.as_ptr(),
                output_buffer.as_mut_ptr(),
                BUFFER_SIZE as c_int,
            )
        };

        if result < 0 {
            return Err(Error::bypass_failed(
                format!("{:?}", mode),
                format!("IRa1n_Execute returned error code: {}", result),
            ));
        }

        let len = output_buffer.iter().position(|&c| c == 0).unwrap_or(BUFFER_SIZE);
        let output = String::from_utf8_lossy(
            &output_buffer[..len]
                .iter()
                .map(|&c| c as u8)
                .collect::<Vec<u8>>(),
        )
        .into_owned();

        let result: IRa1nResult = serde_json::from_str(&output)?;
        Ok(result)
    }

    /// Execute iRa1n operation via CLI (iRa1n.exe)
    pub async fn execute_cli(
        &mut self,
        mode: IRa1nMode,
        bypass_type: Option<IRa1nBypassType>,
    ) -> Result<IRa1nResult> {
        let exe_path = self.find_exe()?;

        let mut args = vec![];

        match mode {
            IRa1nMode::ExploitOnly => args.push("--exploit-only"),
            IRa1nMode::FullBypass => args.push("--full-bypass"),
            IRa1nMode::EnterRecovery => args.push("--enter-recovery"),
            IRa1nMode::ExitRecovery => args.push("--exit-recovery"),
            IRa1nMode::Backup => args.push("--backup"),
            IRa1nMode::Restore => args.push("--restore"),
            IRa1nMode::Info => args.push("--info"),
        }

        if let Some(bt) = bypass_type {
            args.push("--bypass-type");
            args.push(match bt {
                IRa1nBypassType::iCloud => "icloud",
                IRa1nBypassType::Passcode => "passcode",
                IRa1nBypassType::MDM => "mdm",
                IRa1nBypassType::FileAccess => "fileaccess",
                IRa1nBypassType::All => "all",
            });
        }

        if let Some(udid) = &self.config.device_udid {
            args.push("--udid");
            args.push(udid);
        }

        if self.config.verbose {
            args.push("--verbose");
        }

        if self.config.skip_backup {
            args.push("--skip-backup");
        }

        if let Some(ramdisk) = &self.config.custom_ramdisk {
            args.push("--ramdisk");
            args.push(ramdisk);
        }

        if let Some(ios) = &self.config.target_ios_version {
            args.push("--ios-version");
            args.push(ios);
        }

        info!("Executing iRa1n: {} {}", exe_path.display(), args.join(" "));

        let mut cmd = tokio::process::Command::new(&exe_path);
        cmd.args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let output = cmd.output().await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() {
            return Err(Error::bypass_failed(
                format!("{:?}", mode),
                format!("iRa1n.exe failed: {}", stderr),
            ));
        }

        // Parse JSON output
        let result: IRa1nResult = serde_json::from_str(&stdout)
            .context("Failed to parse iRa1n output")?;

        Ok(result)
    }

    /// Find iRa1n.exe
    fn find_exe(&self) -> Result<std::path::PathBuf> {
        if let Some(exe_path) = &self.config.exe_path {
            let path = Path::new(exe_path);
            if path.exists() {
                return Ok(path.to_path_buf());
            }
        }

        let search_paths = [
            std::env::current_dir()?.join("iRa1n.exe"),
            std::env::current_exe()?
                .parent()
                .unwrap_or(&std::path::PathBuf::new())
                .join("iRa1n.exe"),
            std::path::PathBuf::from(r"C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\ref\ira1n\iRa1n.exe"),
        ];

        for path in &search_paths {
            if path.exists() {
                return Ok(path.clone());
            }
        }

        Err(Error::native_library("iRa1n.exe not found"))
    }

    /// Run full bypass operation
    pub async fn full_bypass(
        &mut self,
        bypass_type: IRa1nBypassType,
    ) -> Result<IRa1nResult> {
        // Try DLL first, fallback to CLI
        if self.library.is_some() {
            let params = serde_json::json!({
                "bypass_type": bypass_type as i32,
                "device_udid": self.config.device_udid,
                "skip_backup": self.config.skip_backup,
                "custom_ramdisk": self.config.custom_ramdisk,
                "target_ios_version": self.config.target_ios_version,
            });
            return self.execute_dll(IRa1nMode::FullBypass, &params.to_string());
        }

        self.execute_cli(IRa1nMode::FullBypass, Some(bypass_type)).await
    }

    /// Get device info
    pub async fn get_device_info(&mut self) -> Result<DeviceInfo> {
        let result = if self.library.is_some() {
            self.execute_dll(IRa1nMode::Info, "{}")?
        } else {
            self.execute_cli(IRa1nMode::Info, None).await?
        };

        result.device_info.ok_or_else(|| {
            Error::device_not_found("No device info returned from iRa1n")
        })
    }

    /// Enter recovery mode
    pub async fn enter_recovery(&mut self) -> Result<IRa1nResult> {
        if self.library.is_some() {
            return self.execute_dll(IRa1nMode::EnterRecovery, "{}");
        }
        self.execute_cli(IRa1nMode::EnterRecovery, None).await
    }

    /// Exit recovery mode
    pub async fn exit_recovery(&mut self) -> Result<IRa1nResult> {
        if self.library.is_some() {
            return self.execute_dll(IRa1nMode::ExitRecovery, "{}");
        }
        self.execute_cli(IRa1nMode::ExitRecovery, None).await
    }

    /// Check if iRa1n components are available
    pub fn check_availability(&self) -> AvailabilityReport {
        let mut report = AvailabilityReport::default();

        report.dll_available = self.library.is_some();
        report.exe_available = self.find_exe().is_ok();

        if let Ok(lib_dir) = &self.config.libimobiledevice_dir {
            report.libimobiledevice_available = Path::new(lib_dir).join("libimobiledevice-1.0.dll").exists();
            report.libirecovery_available = Path::new(lib_dir).join("libirecovery-1.0.dll").exists();
            report.libplist_available = Path::new(lib_dir).join("libplist-2.0.dll").exists();
            report.libusbmuxd_available = Path::new(lib_dir).join("libusbmuxd-2.0.dll").exists();
        } else {
            // Check default location
            let default_dir = Path::new(r"C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\ref\ira1n\bin");
            report.libimobiledevice_available = default_dir.join("libimobiledevice-1.0.dll").exists();
            report.libirecovery_available = default_dir.join("libirecovery-1.0.dll").exists();
            report.libplist_available = default_dir.join("libplist-2.0.dll").exists();
            report.libusbmuxd_available = default_dir.join("libusbmuxd-2.0.dll").exists();
        }

        report.data_dll_available = self.config.data_dll_path.as_ref()
            .map(|p| Path::new(p).exists())
            .unwrap_or_else(|| {
                Path::new(r"C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\ref\ira1n\Data.dll").exists()
            });

        report
    }
}

/// Availability report for iRa1n components
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AvailabilityReport {
    pub dll_available: bool,
    pub exe_available: bool,
    pub data_dll_available: bool,
    pub libimobiledevice_available: bool,
    pub libirecovery_available: bool,
    pub libplist_available: bool,
    pub libusbmuxd_available: bool,
}

impl AvailabilityReport {
    /// Check if all required components are available
    pub fn is_complete(&self) -> bool {
        self.dll_available
            || (self.exe_available
                && self.libimobiledevice_available
                && self.libirecovery_available
                && self.libplist_available
                && self.libusbmuxd_available)
    }

    /// Get missing components
    pub fn missing(&self) -> Vec<String> {
        let mut missing = Vec::new();
        if !self.dll_available && !self.exe_available {
            missing.push("ira1n.dll or iRa1n.exe".to_string());
        }
        if !self.data_dll_available {
            missing.push("Data.dll".to_string());
        }
        if !self.libimobiledevice_available {
            missing.push("libimobiledevice-1.0.dll".to_string());
        }
        if !self.libirecovery_available {
            missing.push("libirecovery-1.0.dll".to_string());
        }
        if !self.libplist_available {
            missing.push("libplist-2.0.dll".to_string());
        }
        if !self.libusbmuxd_available {
            missing.push("libusbmuxd-2.0.dll".to_string());
        }
        missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ira1n_config_default() {
        let config = IRa1nConfig::default();
        assert!(config.dll_path.is_none());
        assert!(!config.verbose);
    }

    #[test]
    fn test_ira1n_mode_values() {
        assert_eq!(IRa1nMode::ExploitOnly as i32, 0);
        assert_eq!(IRa1nMode::FullBypass as i32, 1);
    }

    #[test]
    fn test_bypass_type_values() {
        assert_eq!(IRa1nBypassType::iCloud as i32, 0);
        assert_eq!(IRa1nBypassType::All as i32, 4);
    }
}