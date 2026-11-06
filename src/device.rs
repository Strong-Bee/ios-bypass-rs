//! Device detection, enumeration, and management

use std::collections::HashMap;
use std::ffi::{c_void, CStr, CString};
use std::mem;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libc::{c_char, c_int, c_uint, c_ulong};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::error::{Error, Result};

/// Device connection type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum ConnectionType {
    USB = 0,
    WiFi = 1,
    Network = 2,
}

/// Device state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum DeviceState {
    Unknown = 0,
    Normal = 1,           // Normal iOS mode
    Recovery = 2,         // Recovery mode (iBoot)
    DFU = 3,              // DFU mode (SecureROM)
    Exploited = 4,        // Post-exploitation (checkm8)
    RamdiskBooted = 5,    // Custom ramdisk booted
    BypassActive = 6,     // Bypass in progress
    BypassComplete = 7,   // Bypass completed
    Error = 255,
}

/// Device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Unique Device ID (40-char hex)
    pub udid: String,
    /// Device name
    pub name: Option<String>,
    /// Marketing model (e.g., "iPhone 12 Pro")
    pub model: String,
    /// Internal model identifier (e.g., "iPhone13,3")
    pub model_id: String,
    /// iOS version (e.g., "15.4.1")
    pub ios_version: String,
    /// Build version (e.g., "19E258")
    pub build_version: Option<String>,
    /// Serial number
    pub serial_number: Option<String>,
    /// IMEI (for cellular models)
    pub imei: Option<String>,
    /// ECID (Exclusive Chip ID)
    pub ecid: Option<String>,
    /// WiFi MAC address
    pub wifi_address: Option<String>,
    /// Bluetooth MAC address
    pub bluetooth_address: Option<String>,
    /// Connection type
    pub connection_type: ConnectionType,
    /// Current device state
    pub state: DeviceState,
    /// Is device supervised (MDM enrolled)
    pub is_supervised: bool,
    /// Activation state
    pub activation_state: String,
    /// Passcode enabled
    pub passcode_enabled: bool,
    /// MDM locked
    pub mdm_locked: bool,
    /// iCloud activation locked
    pub icloud_locked: bool,
    /// Supported bypass types
    pub supported_bypasses: Vec<BypassType>,
    /// Hardware architecture
    pub architecture: String,
    /// Chip ID (e.g., "T8010" for A14)
    pub chip_id: Option<String>,
    /// Board ID
    pub board_id: Option<String>,
    /// CPID (Chip ID)
    pub cpid: Option<String>,
    /// BDID (Board ID)
    pub bdid: Option<String>,
}

/// Bypass types supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum BypassType {
    iCloud = 0,
    Passcode = 1,
    MDM = 2,
    FileAccess = 3,
    All = 4,
}

impl BypassType {
    /// Get all bypass types except All
    pub fn all_individual() -> Vec<Self> {
        vec![Self::iCloud, Self::Passcode, Self::MDM, Self::FileAccess]
    }

    /// Check if device supports this bypass (based on chip/architecture)
    pub fn is_supported_on(&self, chip_id: &str, ios_version: &str) -> bool {
        // checkm8 supports A5-A11 (iPhone 4s through iPhone X)
        let supported_chips = [
            "S5L8940", // A5
            "S5L8942", // A5 (rev)
            "S5L8945", // A5X
            "S5L8947", // A5X (rev)
            "S5L8950", // A6
            "S5L8955", // A6X
            "S5L8960", // A7
            "S5L8965", // A8
            "S5L8970", // A8X
            "S5L8975", // A9
            "S5L8976", // A9 (rev)
            "S5L8980", // A10
            "S5L8985", // A10X
            "S5L8990", // A11
        ];

        let chip_supported = supported_chips.iter().any(|c| chip_id.contains(c));

        // iOS version check - checkm8 works on all iOS versions for supported devices
        // but some bypass features need specific iOS versions
        match self {
            BypassType::iCloud => chip_supported,
            BypassType::Passcode => chip_supported,
            BypassType::MDM => chip_supported,
            BypassType::FileAccess => chip_supported,
            BypassType::All => chip_supported,
        }
    }
}

/// Device manager for enumeration and monitoring
pub struct DeviceManager {
    /// libimobiledevice context (if available)
    libimobiledevice: Option<LibiMobileDeviceContext>,
    /// Cached device list
    cache: Arc<Mutex<HashMap<String, DeviceInfo>>>,
    /// Poll interval for device monitoring
    poll_interval: Duration,
}

impl DeviceManager {
    /// Create new device manager
    pub fn new() -> Result<Self> {
        let libimobiledevice = LibiMobileDeviceContext::new().ok();

        Ok(Self {
            libimobiledevice,
            cache: Arc::new(Mutex::new(HashMap::new())),
            poll_interval: Duration::from_secs(2),
        })
    }

    /// Set poll interval
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Scan for connected devices
    pub async fn scan(&self) -> Result<Vec<DeviceInfo>> {
        let mut devices = Vec::new();

        // Try libimobiledevice first
        if let Some(ctx) = &self.libimobiledevice {
            if let Ok(found) = ctx.enumerate_devices().await {
                devices.extend(found);
            }
        }

        // Fallback: try using irecovery/idevice tools
        if devices.is_empty() {
            devices.extend(self.scan_via_tools().await?);
        }

        // Update cache
        {
            let mut cache = self.cache.lock().unwrap();
            cache.clear();
            for device in &devices {
                cache.insert(device.udid.clone(), device.clone());
            }
        }

        Ok(devices)
    }

    /// Scan using command-line tools
    async fn scan_via_tools(&self) -> Result<Vec<DeviceInfo>> {
        let mut devices = Vec::new();

        // Try idevice_id -l
        if let Ok(output) = tokio::process::Command::new("idevice_id")
            .arg("-l")
            .output()
            .await
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let udid = line.trim();
                    if !udid.is_empty() && udid.len() == 40 {
                        if let Ok(info) = self.get_device_info(udid).await {
                            devices.push(info);
                        }
                    }
                }
            }
        }

        // Try irecovery -q for DFU/Recovery devices
        if let Ok(output) = tokio::process::Command::new("irecovery")
            .arg("-q")
            .output()
            .await
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(device) = Self::parse_irecovery_output(&stdout) {
                    devices.push(device);
                }
            }
        }

        Ok(devices)
    }

    /// Parse irecovery -q output
    fn parse_irecovery_output(output: &str) -> Option<DeviceInfo> {
        let mut info = DeviceInfo::default();
        info.state = DeviceState::DFU;

        for line in output.lines() {
            let parts: Vec<&str> = line.split(':').map(|s| s.trim()).collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "CPID" => info.cpid = Some(parts[1].to_string()),
                    "BDID" => info.bdid = Some(parts[1].to_string()),
                    "ECID" => info.ecid = Some(parts[1].to_string()),
                    "MODEL" => info.model_id = parts[1].to_string(),
                    "IBEC" | "iBSS" => {
                        // In DFU/Recovery mode
                    }
                    _ => {}
                }
            }
        }

        // Try to get UDID from other sources
        if info.udid.is_empty() {
            // Generate placeholder
            info.udid = format!("DFU_DEVICE_{}", info.ecid.as_deref().unwrap_or("UNKNOWN"));
        }

        Some(info)
    }

    /// Get detailed device info
    pub async fn get_device_info(&self, udid: &str) -> Result<DeviceInfo> {
        // Check cache first
        {
            let cache = self.cache.lock().unwrap();
            if let Some(device) = cache.get(udid) {
                return Ok(device.clone());
            }
        }

        // Try to get info via ideviceinfo
        let output = tokio::process::Command::new("ideviceinfo")
            .arg("-u")
            .arg(udid)
            .output()
            .await
            .context("Failed to run ideviceinfo")?;

        if !output.status.success() {
            return Err(Error::device_not_found(format!(
                "ideviceinfo failed for {}",
                udid
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut device = Self::parse_ideviceinfo(&stdout, udid)?;

        // Determine supported bypasses based on hardware
        device.supported_bypasses = Self::determine_supported_bypasses(&device);

        Ok(device)
    }

    /// Parse ideviceinfo output
    fn parse_ideviceinfo(output: &str, udid: &str) -> Result<DeviceInfo> {
        let mut device = DeviceInfo {
            udid: udid.to_string(),
            ..Default::default()
        };

        for line in output.lines() {
            let parts: Vec<&str> = line.split(':').map(|s| s.trim()).collect();
            if parts.len() >= 2 {
                let key = parts[0];
                let value = parts[1..].join(":").trim().to_string();

                match key {
                    "DeviceName" => device.name = Some(value),
                    "ProductType" => device.model_id = value.clone(),
                    "ProductVersion" => device.ios_version = value,
                    "BuildVersion" => device.build_version = Some(value),
                    "SerialNumber" => device.serial_number = Some(value),
                    "InternationalMobileEquipmentIdentity" => device.imei = Some(value),
                    "UniqueChipID" | "ChipID" => device.ecid = Some(value),
                    "WiFiAddress" => device.wifi_address = Some(value),
                    "BluetoothAddress" => device.bluetooth_address = Some(value),
                    "ActivationState" => device.activation_state = value,
                    "PasswordProtected" => device.passcode_enabled = value == "true",
                    "Supervised" => device.is_supervised = value == "true",
                    "MobileDeviceManagement" => device.mdm_locked = value == "true",
                    "CloudActivationLock" => device.icloud_locked = value == "true",
                    "HardwareModel" => {
                        // Map hardware model to marketing name
                        device.model = Self::hardware_model_to_name(&value);
                        device.architecture = Self::hardware_model_to_arch(&value);
                        device.chip_id = Some(Self::hardware_model_to_chip(&value));
                    }
                    _ => {}
                }
            }
        }

        // Determine state
        device.state = Self::determine_state(&device);

        Ok(device)
    }

    /// Map hardware model to marketing name
    fn hardware_model_to_name(model: &str) -> String {
        let models = [
            ("iPhone1,1", "iPhone 2G"),
            ("iPhone1,2", "iPhone 3G"),
            ("iPhone2,1", "iPhone 3GS"),
            ("iPhone3,1", "iPhone 4"),
            ("iPhone3,2", "iPhone 4 (GSM)"),
            ("iPhone3,3", "iPhone 4 (CDMA)"),
            ("iPhone4,1", "iPhone 4S"),
            ("iPhone5,1", "iPhone 5 (GSM)"),
            ("iPhone5,2", "iPhone 5 (CDMA)"),
            ("iPhone5,3", "iPhone 5c (GSM)"),
            ("iPhone5,4", "iPhone 5c (CDMA)"),
            ("iPhone6,1", "iPhone 5s (GSM)"),
            ("iPhone6,2", "iPhone 5s (CDMA)"),
            ("iPhone7,1", "iPhone 6 Plus"),
            ("iPhone7,2", "iPhone 6"),
            ("iPhone8,1", "iPhone 6s"),
            ("iPhone8,2", "iPhone 6s Plus"),
            ("iPhone8,4", "iPhone SE (1st gen)"),
            ("iPhone9,1", "iPhone 7 (GSM)"),
            ("iPhone9,2", "iPhone 7 Plus (GSM)"),
            ("iPhone9,3", "iPhone 7 (CDMA)"),
            ("iPhone9,4", "iPhone 7 Plus (CDMA)"),
            ("iPhone10,1", "iPhone 8 (GSM)"),
            ("iPhone10,2", "iPhone 8 Plus (GSM)"),
            ("iPhone10,3", "iPhone X (GSM)"),
            ("iPhone10,4", "iPhone 8 (CDMA)"),
            ("iPhone10,5", "iPhone 8 Plus (CDMA)"),
            ("iPhone10,6", "iPhone X (CDMA)"),
            ("iPhone11,2", "iPhone XS"),
            ("iPhone11,4", "iPhone XS Max"),
            ("iPhone11,6", "iPhone XS Max (China)"),
            ("iPhone11,8", "iPhone XR"),
            ("iPhone12,1", "iPhone 11"),
            ("iPhone12,3", "iPhone 11 Pro"),
            ("iPhone12,5", "iPhone 11 Pro Max"),
            ("iPhone12,8", "iPhone SE (2nd gen)"),
            ("iPhone13,1", "iPhone 12 mini"),
            ("iPhone13,2", "iPhone 12"),
            ("iPhone13,3", "iPhone 12 Pro"),
            ("iPhone13,4", "iPhone 12 Pro Max"),
            ("iPhone14,2", "iPhone 13 Pro"),
            ("iPhone14,3", "iPhone 13 Pro Max"),
            ("iPhone14,4", "iPhone 13 mini"),
            ("iPhone14,5", "iPhone 13"),
            ("iPhone14,6", "iPhone SE (3rd gen)"),
            ("iPhone14,7", "iPhone 14"),
            ("iPhone14,8", "iPhone 14 Plus"),
            ("iPhone15,2", "iPhone 14 Pro"),
            ("iPhone15,3", "iPhone 14 Pro Max"),
            ("iPhone15,4", "iPhone 15"),
            ("iPhone15,5", "iPhone 15 Plus"),
            ("iPhone16,1", "iPhone 15 Pro"),
            ("iPhone16,2", "iPhone 15 Pro Max"),
        ];

        models
            .iter()
            .find(|(k, _)| *k == model)
            .map(|(_, v)| v.to_string())
            .unwrap_or_else(|| model.to_string())
    }

    /// Map hardware model to architecture
    fn hardware_model_to_arch(model: &str) -> String {
        if model.starts_with("iPhone1,")
            || model.starts_with("iPhone2,")
            || model.starts_with("iPhone3,")
            || model.starts_with("iPhone4,")
        {
            "armv7".to_string()
        } else if model.starts_with("iPhone5,")
            || model.starts_with("iPhone6,")
            || model.starts_with("iPhone7,")
            || model.starts_with("iPhone8,")
        {
            "arm64".to_string()
        } else {
            "arm64".to_string()
        }
    }

    /// Map hardware model to chip ID
    fn hardware_model_to_chip(model: &str) -> String {
        let chips = [
            ("iPhone1,1", "S5L8900"), // A5
            ("iPhone1,2", "S5L8900"),
            ("iPhone2,1", "S5L8920"), // A5
            ("iPhone3,1", "S5L8930"), // A4
            ("iPhone3,2", "S5L8930"),
            ("iPhone3,3", "S5L8930"),
            ("iPhone4,1", "S5L8940"), // A5
            ("iPhone5,1", "S5L8950"), // A6
            ("iPhone5,2", "S5L8950"),
            ("iPhone5,3", "S5L8950"),
            ("iPhone5,4", "S5L8950"),
            ("iPhone6,1", "S5L8960"), // A7
            ("iPhone6,2", "S5L8960"),
            ("iPhone7,1", "S5L8970"), // A8
            ("iPhone7,2", "S5L8970"),
            ("iPhone8,1", "S5L8980"), // A9
            ("iPhone8,2", "S5L8980"),
            ("iPhone8,4", "S5L8980"),
            ("iPhone9,1", "S5L8990"), // A10
            ("iPhone9,2", "S5L8990"),
            ("iPhone9,3", "S5L8990"),
            ("iPhone9,4", "S5L8990"),
            ("iPhone10,1", "T8010"),  // A11
            ("iPhone10,2", "T8010"),
            ("iPhone10,3", "T8010"),
            ("iPhone10,4", "T8010"),
            ("iPhone10,5", "T8010"),
            ("iPhone10,6", "T8010"),
            ("iPhone11,2", "T8015"),  // A12
            ("iPhone11,4", "T8015"),
            ("iPhone11,6", "T8015"),
            ("iPhone11,8", "T8015"),
            ("iPhone12,1", "T8020"),  // A13
            ("iPhone12,3", "T8020"),
            ("iPhone12,5", "T8020"),
            ("iPhone12,8", "T8020"),
            ("iPhone13,1", "T8101"),  // A14
            ("iPhone13,2", "T8101"),
            ("iPhone13,3", "T8101"),
            ("iPhone13,4", "T8101"),
            ("iPhone14,2", "T8110"),  // A15
            ("iPhone14,3", "T8110"),
            ("iPhone14,4", "T8110"),
            ("iPhone14,5", "T8110"),
            ("iPhone14,6", "T8110"),
            ("iPhone14,7", "T8110"),
            ("iPhone14,8", "T8110"),
            ("iPhone15,2", "T8120"),  // A16
            ("iPhone15,3", "T8120"),
            ("iPhone15,4", "T8120"),
            ("iPhone15,5", "T8120"),
            ("iPhone16,1", "T8130"),  // A17
            ("iPhone16,2", "T8130"),
        ];

        chips
            .iter()
            .find(|(k, _)| *k == model)
            .map(|(_, v)| v.to_string())
            .unwrap_or_else(|| "Unknown".to_string())
    }

    /// Determine device state from info
    fn determine_state(device: &DeviceInfo) -> DeviceState {
        // Check if in recovery/DFU via activation state
        match device.activation_state.as_str() {
            "Unactivated" => DeviceState::Recovery,
            "Activated" => DeviceState::Normal,
            _ => DeviceState::Unknown,
        }
    }

    /// Determine supported bypasses based on device capabilities
    fn determine_supported_bypasses(device: &DeviceInfo) -> Vec<BypassType> {
        let mut bypasses = Vec::new();

        // Check if device is checkm8 vulnerable (A5-A11)
        if let Some(chip) = &device.chip_id {
            let vulnerable_chips = [
                "S5L8940", "S5L8942", "S5L8945", "S5L8947", // A5/A5X
                "S5L8950", "S5L8955", // A6/A6X
                "S5L8960", // A7
                "S5L8965", // A8
                "S5L8970", "S5L8975", "S5L8976", // A8X/A9
                "S5L8980", "S5L8985", // A10/A10X
                "S5L8990", // A11
            ];

            if vulnerable_chips.iter().any(|c| chip.contains(c)) {
                bypasses.push(BypassType::iCloud);
                bypasses.push(BypassType::Passcode);
                bypasses.push(BypassType::MDM);
                bypasses.push(BypassType::FileAccess);
            }
        }

        bypasses
    }

    /// Wait for device to appear
    pub async fn wait_for_device(
        &self,
        timeout_duration: Duration,
    ) -> Result<DeviceInfo> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout_duration {
            let devices = self.scan().await?;
            if let Some(device) = devices.first() {
                return Ok(device.clone());
            }
            tokio::time::sleep(self.poll_interval).await;
        }

        Err(Error::Timeout {
            seconds: timeout_duration.as_secs(),
            context: "Waiting for device".to_string(),
        })
    }

    /// Monitor device state changes
    pub async fn monitor<F>(&self, mut callback: F) -> Result<()>
    where
        F: FnMut(&DeviceInfo) + Send + 'static,
    {
        let mut last_devices: HashMap<String, DeviceInfo> = HashMap::new();

        loop {
            let devices = self.scan().await?;
            let current: HashMap<String, DeviceInfo> = devices
                .into_iter()
                .map(|d| (d.udid.clone(), d))
                .collect();

            // Check for new devices
            for (udid, device) in &current {
                if !last_devices.contains_key(udid) {
                    callback(device);
                }
            }

            // Check for removed devices
            for udid in last_devices.keys() {
                if !current.contains_key(udid) {
                    // Device disconnected
                }
            }

            // Check for state changes
            for (udid, device) in &current {
                if let Some(last) = last_devices.get(udid) {
                    if last.state != device.state {
                        callback(device);
                    }
                }
            }

            last_devices = current;
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

impl Default for DeviceInfo {
    fn default() -> Self {
        Self {
            udid: String::new(),
            name: None,
            model: String::new(),
            model_id: String::new(),
            ios_version: String::new(),
            build_version: None,
            serial_number: None,
            imei: None,
            ecid: None,
            wifi_address: None,
            bluetooth_address: None,
            connection_type: ConnectionType::USB,
            state: DeviceState::Unknown,
            is_supervised: false,
            activation_state: String::new(),
            passcode_enabled: false,
            mdm_locked: false,
            icloud_locked: false,
            supported_bypasses: Vec::new(),
            architecture: String::new(),
            chip_id: None,
            board_id: None,
            cpid: None,
            bdid: None,
        }
    }
}

/// libimobiledevice context wrapper (if available)
struct LibiMobileDeviceContext {
    // Handle to loaded library
    handle: *mut c_void,
    // Function pointers
    idevice_new: Option<unsafe extern "system" fn(*mut *mut c_void, *const c_char) -> c_int>,
    idevice_free: Option<unsafe extern "system" fn(*mut c_void) -> c_int>,
    idevice_get_device_list: Option<
        unsafe extern "system" fn(*mut *mut *mut c_char, *mut c_int) -> c_int,
    >,
    idevice_device_list_free: Option<unsafe extern "system" fn(*mut *mut c_char) -> c_int>,
    idevice_get_udid: Option<unsafe extern "system" fn(*mut c_void, *mut *mut c_char) -> c_int>,
}

impl LibiMobileDeviceContext {
    fn new() -> Result<Self> {
        // Try to load libimobiledevice-1.0.dll
        let paths = [
            "libimobiledevice-1.0.dll",
            r"C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\ref\ira1n\bin\libimobiledevice-1.0.dll",
        ];

        for path in &paths {
            if Path::new(path).exists() {
                #[cfg(windows)]
                {
                    use std::os::windows::ffi::OsStrExt;
                    let wide_path: Vec<u16> =
                        Path::new(path).as_os_str().encode_wide().chain(Some(0)).collect();
                    let handle =
                        unsafe { winapi::um::libloaderapi::LoadLibraryW(wide_path.as_ptr()) };
                    if !handle.is_null() {
                        return Ok(Self::load_symbols(handle));
                    }
                }
                #[cfg(not(windows))]
                {
                    use std::os::unix::ffi::OsStrExt;
                    let c_path = std::ffi::CString::new(Path::new(path).as_os_str().as_bytes())?;
                    let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_LAZY) };
                    if !handle.is_null() {
                        return Ok(Self::load_symbols(handle));
                    }
                }
            }
        }

        Err(Error::native_library("libimobiledevice not found"))
    }

    fn load_symbols(handle: *mut c_void) -> Self {
        macro_rules! get_sym {
            ($handle:expr, $name:expr) => {{
                let c_name = CString::new($name).ok();
                c_name.and_then(|n| {
                    #[cfg(windows)]
                    let sym = unsafe { winapi::um::libloaderapi::GetProcAddress($handle, n.as_ptr()) };
                    #[cfg(not(windows))]
                    let sym = unsafe { libc::dlsym($handle, n.as_ptr()) };
                    if sym.is_null() {
                        None
                    } else {
                        Some(unsafe { mem::transmute(sym) })
                    }
                })
            }};
        }

        Self {
            handle,
            idevice_new: get_sym!(handle, "idevice_new"),
            idevice_free: get_sym!(handle, "idevice_free"),
            idevice_get_device_list: get_sym!(handle, "idevice_get_device_list"),
            idevice_device_list_free: get_sym!(handle, "idevice_device_list_free"),
            idevice_get_udid: get_sym!(handle, "idevice_get_udid"),
        }
    }

    async fn enumerate_devices(&self) -> Result<Vec<DeviceInfo>> {
        let get_list = self
            .idevice_get_device_list
            .ok_or_else(|| Error::function_not_found("idevice_get_device_list", "libimobiledevice"))?;
        let free_list = self
            .idevice_device_list_free
            .ok_or_else(|| Error::function_not_found("idevice_device_list_free", "libimobiledevice"))?;
        let get_udid = self
            .idevice_get_udid
            .ok_or_else(|| Error::function_not_found("idevice_get_udid", "libimobiledevice"))?;

        let mut devices = Vec::new();
        let mut device_list: *mut *mut c_char = std::ptr::null_mut();
        let mut count: c_int = 0;

        let ret = unsafe { get_list(&mut device_list, &mut count) };
        if ret != 0 || count == 0 {
            return Ok(devices);
        }

        for i in 0..count as usize {
            let udid_ptr = unsafe { *device_list.add(i) };
            if !udid_ptr.is_null() {
                let udid = unsafe { CStr::from_ptr(udid_ptr).to_string_lossy().into_owned() };
                if let Ok(info) = self.get_device_info_via_lib(&udid).await {
                    devices.push(info);
                }
            }
        }

        unsafe { free_list(device_list) };
        Ok(devices)
    }

    async fn get_device_info_via_lib(&self, udid: &str) -> Result<DeviceInfo> {
        // Use ideviceinfo tool as fallback since full libimobiledevice binding is complex
        DeviceManager::get_device_info_static(udid).await
    }
}

impl Drop for LibiMobileDeviceContext {
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

impl DeviceManager {
    /// Static version for use without self
    async fn get_device_info_static(udid: &str) -> Result<DeviceInfo> {
        let output = tokio::process::Command::new("ideviceinfo")
            .arg("-u")
            .arg(udid)
            .output()
            .await
            .context("Failed to run ideviceinfo")?;

        if !output.status.success() {
            return Err(Error::device_not_found(format!(
                "ideviceinfo failed for {}",
                udid
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_ideviceinfo(&stdout, udid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_state_values() {
        assert_eq!(DeviceState::Normal as i32, 1);
        assert_eq!(DeviceState::DFU as i32, 3);
    }

    #[test]
    fn test_bypass_type_values() {
        assert_eq!(BypassType::iCloud as i32, 0);
        assert_eq!(BypassType::All as i32, 4);
    }

    #[test]
    fn test_hardware_model_mapping() {
        assert_eq!(
            DeviceManager::hardware_model_to_name("iPhone10,3"),
            "iPhone X (GSM)"
        );
        assert_eq!(
            DeviceManager::hardware_model_to_chip("iPhone10,3"),
            "T8010"
        );
    }
}