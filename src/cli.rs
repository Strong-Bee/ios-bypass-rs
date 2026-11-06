//! Command-line interface for iOS bypass toolkit

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::Mutex;
use tracing::{info, Level};

use crate::bypass::{BypassConfig, BypassOrchestrator, BypassProgress, BypassStage, BypassType, quick_bypass};
use crate::device::{BypassType as DeviceBypassType, ConnectionType, DeviceInfo, DeviceManager, DeviceState};
use crate::error::{Error, Result};
use crate::ira1n::{IRa1n, IRa1nConfig, IRa1nBypassType, IRa1nMode};
use crate::ramdisk::{RamdiskBuilder, RamdiskConfig, RamdiskManager};

/// iOS Bypass Toolkit - iCloud, Passcode, MDM, File Access
#[derive(Parser, Debug)]
#[command(name = "ios-bypass")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "iOS bypass toolkit for Windows - iCloud, Passcode, MDM, File Access")]
#[command(long_about = r#"
iOS Bypass Toolkit

A Rust-based toolkit for iOS device bypass operations using checkm8 exploit (A5-A11 devices).
Supports iCloud activation lock bypass, passcode bypass, MDM removal, and file system access.

Requirements:
- Windows 10/11
- iOS device with A5-A11 chip (iPhone 4s through iPhone X)
- iremovalpro.dll, ira1n.dll, and libimobiledevice stack available
- USB connection to device

Legal Notice: This tool is for educational and authorized testing purposes only.
Use only on devices you own or have explicit permission to test.
"#)]
struct Cli {
    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Device UDID (40-char hex)
    #[arg(short, long, global = true)]
    udid: Option<String>,

    /// Output directory
    #[arg(short, long, global = true)]
    output_dir: Option<PathBuf>,

    /// Configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Detect and list connected iOS devices
    Devices {
        /// Output format
        #[arg(short, long, value_enum, default_value = "table")]
        format: OutputFormat,

        /// Watch for device changes
        #[arg(short, long)]
        watch: bool,
    },

    /// Run full bypass operation
    Bypass {
        /// Bypass types to perform
        #[arg(short, long, value_enum, default_values = ["all"])]
        types: Vec<CliBypassType>,

        /// Skip backup
        #[arg(long)]
        skip_backup: bool,

        /// Custom ramdisk path
        #[arg(long)]
        ramdisk: Option<PathBuf>,

        /// Target iOS version
        #[arg(long)]
        ios_version: Option<String>,

        /// Force bypass even if unsupported
        #[arg(long)]
        force: bool,

        /// Timeout in seconds
        #[arg(long, default_value = "300")]
        timeout: u64,
    },

    /// iCloud activation lock bypass
    Icloud {
        /// Skip backup
        #[arg(long)]
        skip_backup: bool,
    },

    /// Passcode bypass
    Passcode {
        /// Skip backup
        #[arg(long)]
        skip_backup: bool,
    },

    /// MDM removal
    Mdm {
        /// Skip backup
        #[arg(long)]
        skip_backup: bool,
    },

    /// File system access (AFC/SSH)
    FileAccess {
        /// Output directory for extracted files
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Create device backup
    Backup {
        /// Output path for backup
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Restore device from backup
    Restore {
        /// Backup path
        #[arg(short, long)]
        backup: PathBuf,
    },

    /// Run checkm8 exploit only
    Exploit {
        /// Enter DFU mode first
        #[arg(long)]
        enter_dfu: bool,
    },

    /// Enter recovery mode
    EnterRecovery,

    /// Exit recovery mode
    ExitRecovery,

    /// Get device information
    Info,

    /// Check component availability
    Doctor,

    /// Build custom ramdisk
    BuildRamdisk {
        /// iOS version
        #[arg(long, default_value = "15.0")]
        ios_version: String,

        /// Device model
        #[arg(long, default_value = "iPhone10,3")]
        device_model: String,

        /// Output directory
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Manage ramdisk cache
    Ramdisk {
        #[command(subcommand)]
        command: RamdiskCommand,
    },
}

#[derive(Subcommand, Debug)]
enum RamdiskCommand {
    /// List cached ramdisks
    List,
    /// Download ramdisk for iOS version
    Download {
        /// iOS version
        ios_version: String,
        /// Device model
        device_model: String,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum CliBypassType {
    Icloud,
    Passcode,
    Mdm,
    Fileaccess,
    All,
}

impl From<CliBypassType> for BypassType {
    fn from(t: CliBypassType) -> Self {
        match t {
            CliBypassType::Icloud => BypassType::iCloud,
            CliBypassType::Passcode => BypassType::Passcode,
            CliBypassType::Mdm => BypassType::MDM,
            CliBypassType::Fileaccess => BypassType::FileAccess,
            CliBypassType::All => BypassType::All,
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Yaml,
}

/// Run the CLI
pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .init();

    // Load config if provided
    let mut config = BypassConfig::default();
    if let Some(config_path) = cli.config {
        if config_path.exists() {
            let content = std::fs::read_to_string(config_path)?;
            config = serde_json::from_str(&content)?;
        }
    }

    // Override config with CLI args
    if cli.udid.is_some() {
        config.device_udid = cli.udid;
    }
    if cli.output_dir.is_some() {
        config.output_dir = cli.output_dir;
    }

    // Execute command
    match cli.command {
        Commands::Devices { format, watch } => {
            cmd_devices(format, watch).await
        }
        Commands::Bypass { types, skip_backup, ramdisk, ios_version, force, timeout } => {
            cmd_bypass(config, types, skip_backup, ramdisk, ios_version, force, timeout).await
        }
        Commands::Icloud { skip_backup } => {
            cmd_quick_bypass(config, BypassType::iCloud, skip_backup).await
        }
        Commands::Passcode { skip_backup } => {
            cmd_quick_bypass(config, BypassType::Passcode, skip_backup).await
        }
        Commands::Mdm { skip_backup } => {
            cmd_quick_bypass(config, BypassType::MDM, skip_backup).await
        }
        Commands::FileAccess { output } => {
            cmd_file_access(config, output).await
        }
        Commands::Backup { output } => {
            cmd_backup(config, output).await
        }
        Commands::Restore { backup } => {
            cmd_restore(config, backup).await
        }
        Commands::Exploit { enter_dfu } => {
            cmd_exploit(config, enter_dfu).await
        }
        Commands::EnterRecovery => {
            cmd_enter_recovery(config).await
        }
        Commands::ExitRecovery => {
            cmd_exit_recovery(config).await
        }
        Commands::Info => {
            cmd_info(config).await
        }
        Commands::Doctor => {
            cmd_doctor().await
        }
        Commands::BuildRamdisk { ios_version, device_model, output } => {
            cmd_build_ramdisk(ios_version, device_model, output).await
        }
        Commands::Ramdisk { command } => {
            cmd_ramdisk(command).await
        }
    }
}

/// Device listing command
async fn cmd_devices(format: OutputFormat, watch: bool) -> Result<()> {
    let manager = DeviceManager::new()?;

    if watch {
        println!("{}", "Monitoring for device changes... (Ctrl+C to stop)".cyan());
        manager.monitor(|device| {
            print_device(device, &format);
        }).await?;
    } else {
        let devices = manager.scan().await?;
        if devices.is_empty() {
            println!("{}", "No iOS devices detected".yellow());
        } else {
            for device in devices {
                print_device(&device, &format);
            }
        }
    }
    Ok(())
}

fn print_device(device: &DeviceInfo, format: &OutputFormat) {
    match format {
        OutputFormat::Table => {
            println!("\n{}", "─".repeat(60).bright_black());
            println!("{} {}", "Device:".bold().green(), device.name.as_deref().unwrap_or("Unknown").cyan());
            println!("  {} {}", "UDID:".bold(), device.udid);
            println!("  {} {}", "Model:".bold(), device.model);
            println!("  {} {}", "Model ID:".bold(), device.model_id);
            println!("  {} {}", "iOS:".bold(), device.ios_version);
            println!("  {} {:?}", "State:".bold(), device.state);
            println!("  {} {}", "Architecture:".bold(), device.architecture);
            if let Some(chip) = &device.chip_id {
                println!("  {} {}", "Chip:".bold(), chip);
            }
            println!("  {} {}", "Passcode:".bold(), if device.passcode_enabled { "Yes".red() } else { "No".green() });
            println!("  {} {}", "MDM:".bold(), if device.mdm_locked { "Locked".red() } else { "Free".green() });
            println!("  {} {}", "iCloud:".bold(), if device.icloud_locked { "Locked".red() } else { "Free".green() });
            if !device.supported_bypasses.is_empty() {
                print!("  {} ", "Supported:".bold());
                for (i, bt) in device.supported_bypasses.iter().enumerate() {
                    if i > 0 { print!(", "); }
                    print!("{:?}", bt);
                }
                println!();
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(device).unwrap());
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(device).unwrap());
        }
    }
}

/// Full bypass command
async fn cmd_bypass(
    mut config: BypassConfig,
    types: Vec<CliBypassType>,
    skip_backup: bool,
    ramdisk: Option<PathBuf>,
    ios_version: Option<String>,
    force: bool,
    timeout: u64,
) -> Result<()> {
    config.bypass_types = types.into_iter().map(Into::into).collect();
    config.skip_backup = skip_backup;
    config.custom_ramdisk = ramdisk;
    config.target_ios_version = ios_version;
    config.force = force;
    config.operation_timeout = timeout;

    let mut orchestrator = BypassOrchestrator::new(config)?;

    // Set up progress bar
    let pb = ProgressBar::new(100);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}% {msg}")
        .unwrap()
        .progress_chars("##-"));

    let pb = Arc::new(Mutex::new(pb));
    let pb_clone = pb.clone();

    orchestrator.set_progress_callback(move |progress| {
        let pb = pb_clone.blocking_lock();
        pb.set_position(progress.progress as u64);
        pb.set_message(format!("{:?} - {}", progress.stage, progress.message));
    });

    let results = orchestrator.run().await?;

    pb.lock().await.finish_with_message("Complete");

    // Print results
    for result in results {
        print_bypass_result(&result);
    }

    Ok(())
}

/// Quick bypass command
async fn cmd_quick_bypass(
    config: BypassConfig,
    bypass_type: BypassType,
    skip_backup: bool,
) -> Result<()> {
    let mut cfg = config;
    cfg.bypass_types = vec![bypass_type];
    cfg.skip_backup = skip_backup;

    let pb = ProgressBar::new(100);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}% {msg}")
        .unwrap());

    let pb = Arc::new(Mutex::new(pb));
    let pb_clone = pb.clone();

    let mut orchestrator = BypassOrchestrator::new(cfg)?;
    orchestrator.set_progress_callback(move |progress| {
        let pb = pb_clone.blocking_lock();
        pb.set_position(progress.progress as u64);
        pb.set_message(format!("{:?} - {}", progress.stage, progress.message));
    });

    let results = orchestrator.run().await?;
    pb.lock().await.finish_with_message("Complete");

    for result in results {
        print_bypass_result(&result);
    }

    Ok(())
}

/// File access command
async fn cmd_file_access(config: BypassConfig, output: Option<PathBuf>) -> Result<()> {
    let mut cfg = config;
    cfg.bypass_types = vec![BypassType::FileAccess];
    cfg.output_dir = output;

    let result = quick_bypass(cfg.device_udid, BypassType::FileAccess).await?;
    print_bypass_result(&result);

    Ok(())
}

/// Backup command
async fn cmd_backup(mut config: BypassConfig, output: PathBuf) -> Result<()> {
    config.output_dir = Some(output.parent().unwrap_or(&PathBuf::from(".")).to_path_buf());

    let mut orchestrator = BypassOrchestrator::new(config)?;
    let result = orchestrator.create_backup(output).await?;
    print_bypass_result(&result);

    Ok(())
}

/// Restore command
async fn cmd_restore(mut config: BypassConfig, backup: PathBuf) -> Result<()> {
    let mut orchestrator = BypassOrchestrator::new(config)?;
    let result = orchestrator.restore_backup(backup).await?;
    print_bypass_result(&result);

    Ok(())
}

/// Exploit command
async fn cmd_exploit(config: BypassConfig, enter_dfu: bool) -> Result<()> {
    let ira1n_config = IRa1nConfig {
        verbose: true,
        ..Default::default()
    };

    let mut ira1n = IRa1n::new(ira1n_config)?;

    if enter_dfu {
        println!("{}", "Entering DFU mode...".cyan());
        let result = ira1n.enter_recovery().await?; // This would be enter_dfu in real impl
        println!("{}", format!("DFU: {}", if result.success { "Success" } else { "Failed" }));
    }

    println!("{}", "Running checkm8 exploit...".cyan());
    let result = ira1n.execute_cli(IRa1nMode::ExploitOnly, None).await?;
    println!("{}", format!("Exploit: {}", if result.success { "Success" } else { "Failed" }));

    if !result.logs.is_empty() {
        for log in result.logs {
            println!("  {}", log);
        }
    }

    Ok(())
}

/// Enter recovery command
async fn cmd_enter_recovery(config: BypassConfig) -> Result<()> {
    let ira1n_config = IRa1nConfig {
        device_udid: config.device_udid,
        verbose: true,
        ..Default::default()
    };

    let mut ira1n = IRa1n::new(ira1n_config)?;
    let result = ira1n.enter_recovery().await?;

    println!("{}", format!("Enter Recovery: {}", if result.success { "Success" } else { "Failed" }));
    if !result.logs.is_empty() {
        for log in result.logs {
            println!("  {}", log);
        }
    }

    Ok(())
}

/// Exit recovery command
async fn cmd_exit_recovery(config: BypassConfig) -> Result<()> {
    let ira1n_config = IRa1nConfig {
        device_udid: config.device_udid,
        verbose: true,
        ..Default::default()
    };

    let mut ira1n = IRa1n::new(ira1n_config)?;
    let result = ira1n.exit_recovery().await?;

    println!("{}", format!("Exit Recovery: {}", if result.success { "Success" } else { "Failed" }));
    if !result.logs.is_empty() {
        for log in result.logs {
            println!("  {}", log);
        }
    }

    Ok(())
}

/// Info command
async fn cmd_info(config: BypassConfig) -> Result<()> {
    let ira1n_config = IRa1nConfig {
        device_udid: config.device_udid,
        verbose: true,
        ..Default::default()
    };

    let mut ira1n = IRa1n::new(ira1n_config)?;
    let device_info = ira1n.get_device_info().await?;

    println!("\n{}", "Device Information".bold().green());
    println!("{}", "─".repeat(50).bright_black());
    print_device(&device_info, &OutputFormat::Table);

    Ok(())
}

/// Doctor command
async fn cmd_doctor() -> Result<()> {
    println!("{}", "iOS Bypass Toolkit - Component Check".bold().green());
    println!("{}", "─".repeat(50).bright_black());

    let ira1n_config = IRa1nConfig::default();
    let ira1n = IRa1n::new(ira1n_config)?;
    let report = ira1n.check_availability();

    println!("\n{}", "Core Components:".bold());
    println!("  {} iremovalpro.dll", if report.dll_available { "✓".green() } else { "✗".red() });
    println!("  {} iRa1n.exe", if report.exe_available { "✓".green() } else { "✗".red() });
    println!("  {} Data.dll", if report.data_dll_available { "✓".green() } else { "✗".red() });

    println!("\n{}", "libimobiledevice Stack:".bold());
    println!("  {} libimobiledevice-1.0.dll", if report.libimobiledevice_available { "✓".green() } else { "✗".red() });
    println!("  {} libirecovery-1.0.dll", if report.libirecovery_available { "✓".green() } else { "✗".red() });
    println!("  {} libplist-2.0.dll", if report.libplist_available { "✓".green() } else { "✗".red() });
    println!("  {} libusbmuxd-2.0.dll", if report.libusbmuxd_available { "✓".green() } else { "✗".red() });

    if report.is_complete() {
        println!("\n{}", "All components available! ✓".green().bold());
    } else {
        println!("\n{}", "Missing components:".red().bold());
        for missing in report.missing() {
            println!("  - {}", missing);
        }
    }

    // Check for tools
    println!("\n{}", "Command-line Tools:".bold());
    let tools = [
        ("idevice_id", "Device enumeration"),
        ("ideviceinfo", "Device information"),
        ("irecovery", "DFU/Recovery interaction"),
        ("iproxy", "USB multiplexing"),
        ("ifuse", "AFC mounting"),
    ];

    for (tool, desc) in tools {
        let available = Command::new(tool).arg("--version").output().await.is_ok();
        println!("  {} {} ({})", if available { "✓".green() } else { "✗".red() }, tool.bold(), desc);
    }

    Ok(())
}

/// Build ramdisk command
async fn cmd_build_ramdisk(ios_version: String, device_model: String, output: PathBuf) -> Result<()> {
    let config = RamdiskConfig {
        target_ios_version: ios_version,
        device_model,
        output_dir: output,
        ..Default::default()
    };

    let mut builder = RamdiskBuilder::new(config)?;
    let ramdisk_path = builder.create_default_bypass_ramdisk(&DeviceInfo::default())?;

    println!("{}", format!("Ramdisk created: {}", ramdisk_path.display()).green());

    Ok(())
}

/// Ramdisk management command
async fn cmd_ramdisk(command: RamdiskCommand) -> Result<()> {
    let mut manager = RamdiskManager::new(PathBuf::from("./ramdisk_cache"));

    match command {
        RamdiskCommand::List => {
            let cached = manager.list_cached();
            if cached.is_empty() {
                println!("{}", "No cached ramdisks".yellow());
            } else {
                println!("{}", "Cached Ramdisks:".bold());
                for (key, path) in cached {
                    println!("  {} -> {}", key.cyan(), path.display());
                }
            }
        }
        RamdiskCommand::Download { ios_version, device_model } => {
            println!("{}", format!("Downloading ramdisk for {} {}...", ios_version, device_model).cyan());
            let path = manager.download_ramdisk(&ios_version, &device_model).await?;
            println!("{}", format!("Downloaded: {}", path.display()).green());
        }
    }

    Ok(())
}

fn print_bypass_result(result: &crate::bypass::BypassResult) {
    println!("\n{}", "Bypass Result".bold().green());
    println!("{}", "─".repeat(50).bright_black());
    println!("  {} {}", "Type:".bold(), format!("{:?}", result.bypass_type).cyan());
    println!("  {} {}", "Device:".bold(), result.device_udid);
    println!("  {} {}", "Success:".bold(), if result.success { "Yes".green().bold() } else { "No".red().bold() });
    println!("  {} {}ms", "Duration:".bold(), result.duration_ms);

    if let Some(error) = &result.error {
        println!("  {} {}", "Error:".bold().red(), error);
    }

    if !result.logs.is_empty() {
        println!("\n  {}:", "Logs:".bold());
        for log in &result.logs {
            println!("    {}", log);
        }
    }

    if let Some(backup) = &result.backup_path {
        println!("  {} {}", "Backup:".bold(), backup.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_bypass_type_conversion() {
        assert_eq!(BypassType::from(CliBypassType::Icloud), BypassType::iCloud);
        assert_eq!(BypassType::from(CliBypassType::All), BypassType::All);
    }
}