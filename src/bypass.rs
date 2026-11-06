//! High-level bypass operations and orchestration

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::device::{BypassType, DeviceInfo, DeviceState};
use crate::error::{Error, Result};
use crate::ira1n::{IRa1n, IRa1nBypassType, IRa1nConfig, IRa1nResult};
use crate::ramdisk::{RamdiskBuilder, RamdiskConfig};

/// Bypass configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassConfig {
    /// Target device UDID (empty for auto-detect)
    pub device_udid: Option<String>,
    /// Types of bypass to perform
    pub bypass_types: Vec<BypassType>,
    /// Skip backup before bypass
    pub skip_backup: bool,
    /// Custom ramdisk path
    pub custom_ramdisk: Option<PathBuf>,
    /// Target iOS version for ramdisk selection
    pub target_ios_version: Option<String>,
    /// Output directory for backups/logs
    pub output_dir: Option<PathBuf>,
    /// Verbose logging
    pub verbose: bool,
    /// Timeout for each operation (seconds)
    pub operation_timeout: u64,
    /// Retry count for failed operations
    pub retry_count: u32,
    /// Force bypass even if risky
    pub force: bool,
}

impl Default for BypassConfig {
    fn default() -> Self {
        Self {
            device_udid: None,
            bypass_types: vec![BypassType::All],
            skip_backup: false,
            custom_ramdisk: None,
            target_ios_version: None,
            output_dir: None,
            verbose: false,
            operation_timeout: 300,
            retry_count: 3,
            force: false,
        }
    }
}

/// Result of a bypass operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassResult {
    /// Whether the bypass succeeded
    pub success: bool,
    /// Type of bypass performed
    pub bypass_type: BypassType,
    /// Device UDID
    pub device_udid: String,
    /// Device info after bypass
    pub device_info: Option<DeviceInfo>,
    /// Backup path (if created)
    pub backup_path: Option<PathBuf>,
    /// Log messages
    pub logs: Vec<String>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Files extracted (for file access bypass)
    pub extracted_files: Vec<String>,
}

/// Bypass orchestrator
pub struct BypassOrchestrator {
    config: BypassConfig,
    ira1n: IRa1n,
    ramdisk_builder: Option<RamdiskBuilder>,
    progress_callback: Option<Arc<dyn Fn(BypassProgress) + Send + Sync>>,
}

/// Progress updates during bypass
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassProgress {
    pub stage: BypassStage,
    pub progress: u8, // 0-100
    pub message: String,
    pub device_state: DeviceState,
    pub current_bypass: Option<BypassType>,
}

/// Bypass stages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum BypassStage {
    Initializing = 0,
    DetectingDevice = 1,
    EnteringRecovery = 2,
    EnteringDFU = 3,
    RunningExploit = 4,
    BootingRamdisk = 5,
    PreparingBypass = 6,
    ExecutingBypass = 7,
    ExtractingFiles = 8,
    CreatingBackup = 9,
    Finalizing = 10,
    Complete = 11,
    Failed = 255,
}

impl BypassOrchestrator {
    /// Create new bypass orchestrator
    pub fn new(config: BypassConfig) -> Result<Self> {
        let ira1n_config = IRa1nConfig {
            dll_path: None,
            exe_path: None,
            data_dll_path: None,
            libimobiledevice_dir: None,
            verbose: config.verbose,
            skip_backup: config.skip_backup,
            custom_ramdisk: config.custom_ramdisk.clone().map(|p| p.to_string_lossy().to_string()),
            target_ios_version: config.target_ios_version.clone(),
            device_udid: config.device_udid.clone(),
        };

        let ira1n = IRa1n::new(ira1n_config)?;

        // Initialize ramdisk builder if custom ramdisk specified
        let ramdisk_builder = if config.custom_ramdisk.is_some() {
            Some(RamdiskBuilder::new(RamdiskConfig::default())?)
        } else {
            None
        };

        Ok(Self {
            config,
            ira1n,
            ramdisk_builder,
            progress_callback: None,
        })
    }

    /// Set progress callback
    pub fn set_progress_callback<F>(&mut self, callback: F)
    where
        F: Fn(BypassProgress) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Arc::new(callback));
    }

    /// Emit progress update
    fn emit_progress(&self, progress: BypassProgress) {
        if let Some(cb) = &self.progress_callback {
            cb(progress);
        }
    }

    /// Run full bypass operation
    pub async fn run(&mut self) -> Result<Vec<BypassResult>> {
        let start_time = std::time::Instant::now();
        let mut results = Vec::new();

        self.emit_progress(BypassProgress {
            stage: BypassStage::Initializing,
            progress: 0,
            message: "Initializing bypass operation".to_string(),
            device_state: DeviceState::Unknown,
            current_bypass: None,
        });

        // Check component availability
        let availability = self.ira1n.check_availability();
        if !availability.is_complete() {
            let missing = availability.missing();
            return Err(Error::InvalidConfig(format!(
                "Missing required components: {}",
                missing.join(", ")
            )));
        }

        // Detect device
        self.emit_progress(BypassProgress {
            stage: BypassStage::DetectingDevice,
            progress: 10,
            message: "Detecting device...".to_string(),
            device_state: DeviceState::Unknown,
            current_bypass: None,
        });

        let device_info = self.detect_device().await?;
        info!("Detected device: {} ({})", device_info.model, device_info.udid);

        // Check if device supports requested bypasses
        self.validate_device_support(&device_info)?;

        // Process each bypass type
        let bypass_types: Vec<BypassType> = if self.config.bypass_types.contains(&BypassType::All) {
            BypassType::all_individual()
        } else {
            self.config.bypass_types.clone()
        };

        for (i, bypass_type) in bypass_types.iter().enumerate() {
            let progress_base = 20 + (i * 70 / bypass_types.len()) as u8;

            self.emit_progress(BypassProgress {
                stage: BypassStage::PreparingBypass,
                progress: progress_base,
                message: format!("Preparing {:?} bypass...", bypass_type),
                device_state: device_info.state,
                current_bypass: Some(*bypass_type),
            });

            let result = self.execute_bypass(&device_info, *bypass_type).await?;
            results.push(result);
        }

        // Finalize
        self.emit_progress(BypassProgress {
            stage: BypassStage::Finalizing,
            progress: 95,
            message: "Finalizing...".to_string(),
            device_state: DeviceState::BypassComplete,
            current_bypass: None,
        });

        // Complete
        self.emit_progress(BypassProgress {
            stage: BypassStage::Complete,
            progress: 100,
            message: format!("Bypass completed in {:.1}s", start_time.elapsed().as_secs_f32()),
            device_state: DeviceState::BypassComplete,
            current_bypass: None,
        });

        Ok(results)
    }

    /// Detect target device
    async fn detect_device(&self) -> Result<DeviceInfo> {
        use crate::device::DeviceManager;

        let manager = DeviceManager::new()?;
        let devices = manager.scan().await?;

        if let Some(udid) = &self.config.device_udid {
            devices
                .into_iter()
                .find(|d| d.udid == *udid)
                .ok_or_else(|| Error::device_not_found(format!("Device {} not found", udid)))
        } else if let Some(device) = devices.first() {
            Ok(device.clone())
        } else {
            Err(Error::device_not_found("No iOS device detected"))
        }
    }

    /// Validate device supports requested bypasses
    fn validate_device_support(&self, device: &DeviceInfo) -> Result<()> {
        for bypass_type in &self.config.bypass_types {
            if *bypass_type == BypassType::All {
                continue;
            }

            let chip_id = device.chip_id.as_deref().unwrap_or("Unknown");
            let ios_version = &device.ios_version;

            if !bypass_type.is_supported_on(chip_id, ios_version) {
                if !self.config.force {
                    return Err(Error::Unsupported(format!(
                        "{:?} bypass not supported on {} (chip: {}) running iOS {}",
                        bypass_type, device.model, chip_id, ios_version
                    )));
                } else {
                    warn!(
                        "{:?} bypass may not work on {} (chip: {}) running iOS {}",
                        bypass_type, device.model, chip_id, ios_version
                    );
                }
            }
        }

        Ok(())
    }

    /// Execute specific bypass type
    async fn execute_bypass(&mut self, device: &DeviceInfo, bypass_type: BypassType) -> Result<BypassResult> {
        let start = std::time::Instant::now();
        let mut logs = Vec::new();

        logs.push(format!("Starting {:?} bypass on {}", bypass_type, device.udid));

        // Map to iRa1n bypass type
        let ira1n_bypass = match bypass_type {
            BypassType::iCloud => IRa1nBypassType::iCloud,
            BypassType::Passcode => IRa1nBypassType::Passcode,
            BypassType::MDM => IRa1nBypassType::MDM,
            BypassType::FileAccess => IRa1nBypassType::FileAccess,
            BypassType::All => IRa1nBypassType::All,
        };

        // Execute with timeout
        let operation = async {
            // Run the full bypass via iRa1n
            let result = self.ira1n.full_bypass(ira1n_bypass).await?;

            // Collect logs
            logs.extend(result.logs);

            // Get updated device info
            let updated_info = self.ira1n.get_device_info().await.ok();

            // Extract backup path
            let backup_path = result.backup_path.map(PathBuf::from);

            Ok::<_, Error>(BypassResult {
                success: result.success,
                bypass_type,
                device_udid: device.udid.clone(),
                device_info: updated_info,
                backup_path,
                logs: logs.clone(),
                error: if result.success { None } else { Some(result.message) },
                duration_ms: 0, // Will be set after
                extracted_files: Vec::new(), // TODO: populate from file access
            })
        };

        let result = timeout(
            Duration::from_secs(self.config.operation_timeout),
            operation,
        )
        .await
        .map_err(|_| Error::Timeout {
            seconds: self.config.operation_timeout,
            context: format!("{:?} bypass operation", bypass_type),
        })??;

        let mut result = result;
        result.duration_ms = start.elapsed().as_millis() as u64;

        if result.success {
            logs.push(format!("{:?} bypass completed successfully", bypass_type));
        } else {
            logs.push(format!("{:?} bypass failed: {:?}", bypass_type, result.error));
        }

        result.logs = logs;

        Ok(result)
    }

    /// Run iCloud bypass only
    pub async fn run_icloud_bypass(&mut self) -> Result<BypassResult> {
        let device = self.detect_device().await?;
        self.validate_device_support(&device)?;
        self.execute_bypass(&device, BypassType::iCloud).await
    }

    /// Run passcode bypass only
    pub async fn run_passcode_bypass(&mut self) -> Result<BypassResult> {
        let device = self.detect_device().await?;
        self.validate_device_support(&device)?;
        self.execute_bypass(&device, BypassType::Passcode).await
    }

    /// Run MDM removal only
    pub async fn run_mdm_removal(&mut self) -> Result<BypassResult> {
        let device = self.detect_device().await?;
        self.validate_device_support(&device)?;
        self.execute_bypass(&device, BypassType::MDM).await
    }

    /// Run file access only
    pub async fn run_file_access(&mut self) -> Result<BypassResult> {
        let device = self.detect_device().await?;
        self.validate_device_support(&device)?;
        self.execute_bypass(&device, BypassType::FileAccess).await
    }

    /// Create backup of device
    pub async fn create_backup(&mut self, output_path: PathBuf) -> Result<BypassResult> {
        let device = self.detect_device().await?;

        self.emit_progress(BypassProgress {
            stage: BypassStage::CreatingBackup,
            progress: 50,
            message: "Creating device backup...".to_string(),
            device_state: device.state,
            current_bypass: None,
        });

        // Use iRa1n backup mode
        let result = self.ira1n.execute_cli(crate::ira1n::IRa1nMode::Backup, None).await?;

        Ok(BypassResult {
            success: result.success,
            bypass_type: BypassType::FileAccess,
            device_udid: device.udid,
            device_info: result.device_info,
            backup_path: result.backup_path.map(PathBuf::from),
            logs: result.logs,
            error: if result.success { None } else { Some(result.message) },
            duration_ms: 0,
            extracted_files: Vec::new(),
        })
    }

    /// Restore device from backup
    pub async fn restore_backup(&mut self, backup_path: PathBuf) -> Result<BypassResult> {
        let device = self.detect_device().await?;

        self.emit_progress(BypassProgress {
            stage: BypassStage::ExecutingBypass,
            progress: 50,
            message: "Restoring device from backup...".to_string(),
            device_state: device.state,
            current_bypass: None,
        });

        // Use iRa1n restore mode
        let result = self.ira1n.execute_cli(crate::ira1n::IRa1nMode::Restore, None).await?;

        Ok(BypassResult {
            success: result.success,
            bypass_type: BypassType::FileAccess,
            device_udid: device.udid,
            device_info: result.device_info,
            backup_path: Some(backup_path),
            logs: result.logs,
            error: if result.success { None } else { Some(result.message) },
            duration_ms: 0,
            extracted_files: Vec::new(),
        })
    }
}

/// Convenience function for quick bypass
pub async fn quick_bypass(
    device_udid: Option<String>,
    bypass_type: BypassType,
) -> Result<BypassResult> {
    let config = BypassConfig {
        device_udid,
        bypass_types: vec![bypass_type],
        ..Default::default()
    };

    let mut orchestrator = BypassOrchestrator::new(config)?;
    let results = orchestrator.run().await?;

    results.into_iter().next().ok_or_else(|| {
        Error::bypass_failed(
            format!("{:?}", bypass_type),
            "No result returned".to_string(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bypass_config_default() {
        let config = BypassConfig::default();
        assert_eq!(config.bypass_types, vec![BypassType::All]);
        assert!(!config.skip_backup);
    }

    #[test]
    fn test_bypass_stage_values() {
        assert_eq!(BypassStage::Initializing as i32, 0);
        assert_eq!(BypassStage::Complete as i32, 11);
    }
}