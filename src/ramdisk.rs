//! Ramdisk creation and management for iOS bypass
//!
//! Custom ramdisks are used to boot a minimal Linux environment on the device
//! that includes bypass tools, SSH, AFC, and other utilities.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::device::DeviceInfo;
use crate::error::{Error, Result};

/// Ramdisk configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RamdiskConfig {
    /// Base ramdisk directory (contains kernel, initramfs, etc.)
    pub base_dir: Option<PathBuf>,
    /// Output directory for generated ramdisk
    pub output_dir: PathBuf,
    /// Target iOS version
    pub target_ios_version: String,
    /// Target device model (for kernel selection)
    pub device_model: String,
    /// Include SSH server
    pub include_ssh: bool,
    /// Include AFC (Apple File Conduit)
    pub include_afc: bool,
    /// Include bypass scripts
    pub include_bypass_scripts: bool,
    /// Custom kernel path
    pub custom_kernel: Option<PathBuf>,
    /// Custom initramfs path
    pub custom_initramfs: Option<PathBuf>,
    /// Ramdisk size in MB
    pub size_mb: u32,
    /// Compression type
    pub compression: CompressionType,
}

/// Compression types for ramdisk
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum CompressionType {
    None = 0,
    Gzip = 1,
    Lz4 = 2,
    Zstd = 3,
}

impl Default for RamdiskConfig {
    fn default() -> Self {
        Self {
            base_dir: None,
            output_dir: PathBuf::from("./ramdisk_output"),
            target_ios_version: "15.0".to_string(),
            device_model: "iPhone10,3".to_string(), // iPhone X default
            include_ssh: true,
            include_afc: true,
            include_bypass_scripts: true,
            custom_kernel: None,
            custom_initramfs: None,
            size_mb: 256,
            compression: CompressionType::Gzip,
        }
    }
}

/// Ramdisk builder
pub struct RamdiskBuilder {
    config: RamdiskConfig,
    /// Files to include in ramdisk
    files: HashMap<PathBuf, Vec<u8>>,
    /// Scripts to include
    scripts: HashMap<String, String>,
}

impl RamdiskBuilder {
    /// Create new ramdisk builder
    pub fn new(config: RamdiskConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.output_dir)?;

        Ok(Self {
            config,
            files: HashMap::new(),
            scripts: HashMap::new(),
        })
    }

    /// Add file to ramdisk
    pub fn add_file<P: AsRef<Path>>(&mut self, dest_path: P, content: Vec<u8>) {
        self.files.insert(dest_path.as_ref().to_path_buf(), content);
    }

    /// Add script to ramdisk
    pub fn add_script(&mut self, name: &str, content: &str) {
        self.scripts.insert(name.to_string(), content.to_string());
    }

    /// Build the ramdisk
    pub fn build(&mut self) -> Result<PathBuf> {
        info!("Building ramdisk for {} iOS {}", self.config.device_model, self.config.target_ios_version);

        // Create directory structure
        let build_dir = self.config.output_dir.join("build");
        std::fs::create_dir_all(&build_dir)?;

        // Create initramfs structure
        self.create_initramfs_structure(&build_dir)?;

        // Add custom files
        for (dest, content) in &self.files {
            let full_path = build_dir.join(dest.strip_prefix("/").unwrap_or(dest));
            std::fs::create_dir_all(full_path.parent().unwrap())?;
            std::fs::write(&full_path, content)?;
        }

        // Add scripts
        let scripts_dir = build_dir.join("scripts");
        std::fs::create_dir_all(&scripts_dir)?;
        for (name, content) in &self.scripts {
            std::fs::write(scripts_dir.join(name), content)?;
        }

        // Create initramfs
        let initramfs_path = self.config.output_dir.join("initramfs.img");
        self.create_initramfs(&build_dir, &initramfs_path)?;

        // Compress if needed
        let final_path = match self.config.compression {
            CompressionType::None => initramfs_path,
            CompressionType::Gzip => {
                let gz_path = self.config.output_dir.join("initramfs.img.gz");
                self.compress_gzip(&initramfs_path, &gz_path)?;
                gz_path
            }
            CompressionType::Lz4 => {
                let lz4_path = self.config.output_dir.join("initramfs.img.lz4");
                self.compress_lz4(&initramfs_path, &lz4_path)?;
                lz4_path
            }
            CompressionType::Zstd => {
                let zst_path = self.config.output_dir.join("initramfs.img.zst");
                self.compress_zstd(&initramfs_path, &zst_path)?;
                zst_path
            }
        };

        info!("Ramdisk created: {}", final_path.display());
        Ok(final_path)
    }

    /// Create initramfs directory structure
    fn create_initramfs_structure(&self, build_dir: &Path) -> Result<()> {
        let dirs = [
            "bin", "sbin", "etc", "proc", "sys", "dev", "tmp", "var", "root",
            "usr/bin", "usr/sbin", "lib", "lib64", "mnt", "media", "scripts",
        ];

        for dir in &dirs {
            std::fs::create_dir_all(build_dir.join(dir))?;
        }

        // Create basic init script
        let init_script = r#"#!/bin/sh
# iOS Bypass Ramdisk Init
# Mount essential filesystems
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t tmpfs none /tmp
mount -t tmpfs none /var

# Set up networking
ifconfig lo up

# Start SSH if available
if [ -x /usr/sbin/sshd ]; then
    mkdir -p /var/run/sshd
    /usr/sbin/sshd
fi

# Start AFC daemon if available
if [ -x /usr/local/bin/afcd ]; then
    /usr/local/bin/afcd &
fi

# Run bypass scripts
if [ -d /scripts ]; then
    for script in /scripts/*.sh; do
        [ -x "$script" ] && "$script" &
    done
fi

# Keep running
echo "iOS Bypass Ramdisk ready"
exec sh
"#;

        std::fs::write(build_dir.join("init"), init_script)?;
        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(build_dir.join("init"))?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(build_dir.join("init"), perms)?;
        }

        Ok(())
    }

    /// Create initramfs using cpio
    fn create_initramfs(&self, source_dir: &Path, output_path: &Path) -> Result<()> {
        // Use cpio to create initramfs
        let output = Command::new("find")
            .arg(".")
            .arg("-print0")
            .current_dir(source_dir)
            .output()?;

        if !output.status.success() {
            return Err(Error::RamdiskError("Failed to list files".to_string()));
        }

        let cpio_output = Command::new("cpio")
            .args(["-o", "-H", "newc", "--null"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        // This is a simplified version - in reality you'd pipe find output to cpio
        // For now, use a simpler approach
        self.create_initramfs_simple(source_dir, output_path)
    }

    /// Simple initramfs creation (fallback)
    fn create_initramfs_simple(&self, source_dir: &Path, output_path: &Path) -> Result<()> {
        // Use tar as fallback
        let status = Command::new("tar")
            .args(["-cf", output_path.to_str().unwrap(), "-C", source_dir.to_str().unwrap(), "."])
            .status()?;

        if !status.success() {
            return Err(Error::RamdiskError("Failed to create initramfs".to_string()));
        }

        Ok(())
    }

    /// Compress with gzip
    fn compress_gzip(&self, input: &Path, output: &Path) -> Result<()> {
        let status = Command::new("gzip")
            .args(["-c", input.to_str().unwrap()])
            .stdout(std::fs::File::create(output)?)
            .status()?;

        if !status.success() {
            return Err(Error::RamdiskError("Gzip compression failed".to_string()));
        }
        Ok(())
    }

    /// Compress with lz4
    fn compress_lz4(&self, input: &Path, output: &Path) -> Result<()> {
        let status = Command::new("lz4")
            .args([input.to_str().unwrap(), output.to_str().unwrap()])
            .status()?;

        if !status.success() {
            return Err(Error::RamdiskError("LZ4 compression failed".to_string()));
        }
        Ok(())
    }

    /// Compress with zstd
    fn compress_zstd(&self, input: &Path, output: &Path) -> Result<()> {
        let status = Command::new("zstd")
            .args(["-c", input.to_str().unwrap()])
            .stdout(std::fs::File::create(output)?)
            .status()?;

        if !status.success() {
            return Err(Error::RamdiskError("Zstd compression failed".to_string()));
        }
        Ok(())
    }

    /// Create default bypass ramdisk with common tools
    pub fn create_default_bypass_ramdisk(&mut self, device: &DeviceInfo) -> Result<PathBuf> {
        // Add common bypass tools
        self.add_bypass_tools()?;

        // Add device-specific kernel if available
        if let Some(kernel) = self.find_kernel_for_device(device) {
            self.add_file("/kernel", std::fs::read(kernel)?)?;
        }

        self.build()
    }

    /// Add common bypass tools to ramdisk
    fn add_bypass_tools(&mut self) -> Result<()> {
        // Add SSH keys generation script
        self.add_script("generate_ssh_keys.sh", r#"#!/bin/sh
ssh-keygen -A
"#);

        // Add AFC mount script
        self.add_script("mount_afc.sh", r#"#!/bin/sh
mkdir -p /mnt/afc
if [ -x /usr/local/bin/ifuse ]; then
    /usr/local/bin/ifuse /mnt/afc --root
fi
"#);

        // Add bypass script template
        self.add_script("bypass.sh", r#"#!/bin/sh
# Bypass script template
# This will be replaced with actual bypass logic

echo "Starting bypass operations..."

# iCloud bypass
if [ -f /scripts/icloud_bypass.sh ]; then
    /scripts/icloud_bypass.sh
fi

# Passcode bypass
if [ -f /scripts/passcode_bypass.sh ]; then
    /scripts/passcode_bypass.sh
fi

# MDM removal
if [ -f /scripts/mdm_removal.sh ]; then
    /scripts/mdm_removal.sh
fi

echo "Bypass operations completed"
"#);

        Ok(())
    }

    /// Find kernel for device
    fn find_kernel_for_device(&self, device: &DeviceInfo) -> Option<PathBuf> {
        // Check custom kernel first
        if let Some(kernel) = &self.config.custom_kernel {
            if kernel.exists() {
                return Some(kernel.clone());
            }
        }

        // Check base directory for kernel
        if let Some(base) = &self.config.base_dir {
            let kernel_path = base.join("kernels").join(&device.chip_id?).join("kernel");
            if kernel_path.exists() {
                return Some(kernel_path);
            }
        }

        None
    }

    /// Get configuration
    pub fn config(&self) -> &RamdiskConfig {
        &self.config
    }
}

/// Pre-built ramdisk manager for common iOS versions
pub struct RamdiskManager {
    cache_dir: PathBuf,
    available_ramdisks: HashMap<String, PathBuf>,
}

impl RamdiskManager {
    /// Create new ramdisk manager
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            available_ramdisks: HashMap::new(),
        }
    }

    /// Get ramdisk for iOS version and device
    pub fn get_ramdisk(&mut self, ios_version: &str, device_model: &str) -> Option<PathBuf> {
        let key = format!("{}_{}", ios_version, device_model);
        self.available_ramdisks.get(&key).cloned()
    }

    /// Download and cache ramdisk (placeholder)
    pub async fn download_ramdisk(&mut self, ios_version: &str, device_model: &str) -> Result<PathBuf> {
        // In reality, this would download from a trusted source
        // For now, return error
        Err(Error::RamdiskError(
            "Ramdisk download not implemented. Please provide custom ramdisk.".to_string(),
        ))
    }

    /// List available cached ramdisks
    pub fn list_cached(&self) -> Vec<(String, PathBuf)> {
        self.available_ramdisks
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ramdisk_config_default() {
        let config = RamdiskConfig::default();
        assert_eq!(config.size_mb, 256);
        assert!(config.include_ssh);
    }

    #[test]
    fn test_compression_type_values() {
        assert_eq!(CompressionType::Gzip as i32, 1);
        assert_eq!(CompressionType::Zstd as i32, 3);
    }
}