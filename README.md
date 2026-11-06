# iOS Bypass Toolkit (ios-bypass-rs)

A Rust-based toolkit for iOS device bypass operations using the checkm8 bootrom exploit (A5-A11 devices). Provides iCloud activation lock bypass, passcode bypass, MDM removal, and file system access.

## Features

- **iCloud Bypass** - Remove iCloud activation lock on supported devices
- **Passcode Bypass** - Bypass device passcode
- **MDM Removal** - Remove Mobile Device Management profiles
- **File Access** - Access file system via AFC/SSH over USB
- **Device Management** - Detect, enumerate, and monitor iOS devices
- **Cross-platform** - Windows (primary), Linux, macOS support
- **Rust Safety** - Memory-safe FFI bindings with proper error handling

## Supported Devices

Devices with A5-A11 chips (checkm8 vulnerable):
- iPhone 4s through iPhone X (iPhone 10,3/10,6)
- iPad 2 through iPad Pro (1st gen)
- iPod touch 5th-7th gen

## Requirements

### Windows (Primary)
- Windows 10/11 (x64)
- **iremovalpro.dll** - Main bypass library (from iRemoval PRO)
- **ira1n.dll** - checkra1n-based exploit library
- **Data.dll** - Payload data
- **libimobiledevice stack** (in `ref/ira1n/bin/`):
  - libimobiledevice-1.0.dll
  - libirecovery-1.0.dll
  - libplist-2.0.dll
  - libusbmuxd-2.0.dll
  - libusb-1.0.dll
- USB connection to iOS device
- Rust 1.75+

### Linux/macOS
- libimobiledevice, libirecovery, libplist, libusbmuxd, libusb (system packages)
- Same native libraries if available

## Installation

### From Source

```bash
# Clone and build
git clone https://github.com/yourusername/ios-bypass-rs
cd ios-bypass-rs

# Set library paths (if not in default locations)
export IREMOVALPRO_DLL_PATH=/path/to/iremovalpro.dll
export IRA1N_DLL_PATH=/path/to/ira1n.dll
export LIBIMOBILEDEVICE_DIR=/path/to/libimobiledevice/bin

# Build
cargo build --release
```

### Quick Start

```bash
# Check components
ios-bypass doctor

# List connected devices
ios-bypass devices

# Get device info
ios-bypass info

# Run full bypass (all types)
ios-bypass bypass

# Specific bypass types
ios-bypass icloud
ios-bypass passcode
ios-bypass mdm
ios-bypass file-access

# Create backup
ios-bypass backup --output backup.img

# Checkm8 exploit only
ios-bypass exploit --enter-dfu
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ios-bypass-rs (Rust)                     │
├─────────────────────────────────────────────────────────────┤
│  CLI          │  Bypass Orchestrator  │  Device Manager     │
├───────────────┼───────────────────────┼─────────────────────┤
│  iremovalpro  │      iRa1n (checkra1n)│  libimobiledevice   │
│  (P/Invoke)   │      (Exploit + Ramdisk)│  (Device Comm)    │
└───────────────┴───────────────────────┴─────────────────────┘
        │                │                       │
        ▼                ▼                       ▼
   iremovalpro.dll   ira1n.dll + Data.dll   libimobiledevice stack
        │                │                       │
        └────────────────┼───────────────────────┘
                         ▼
              ┌─────────────────────┐
              │   iOS Device (USB)  │
              │  A5-A11 (checkm8)   │
              └─────────────────────┘
```

## Configuration

Create a `config.json`:

```json
{
  "device_udid": "optional_40_char_udid",
  "bypass_types": ["icloud", "passcode", "mdm", "fileaccess"],
  "skip_backup": false,
  "custom_ramdisk": "optional/path/to/ramdisk.img.gz",
  "target_ios_version": "15.0",
  "output_dir": "./output",
  "verbose": true,
  "operation_timeout": 300,
  "retry_count": 3,
  "force": false
}
```

Run with:
```bash
ios-bypass --config config.json bypass
```

## Library Usage

```rust
use ios_bypass_rs::{
    BypassOrchestrator, BypassConfig, BypassType,
    IRa1n, IRa1nConfig, IRa1nBypassType,
    DeviceManager, DeviceInfo,
    IremovalPro, WinInfo,
    Result,
};

#[tokio::main]
async fn main() -> Result<()> {
    // High-level bypass
    let config = BypassConfig {
        device_udid: None, // auto-detect
        bypass_types: vec![BypassType::iCloud, BypassType::Passcode],
        ..Default::default()
    };

    let mut orchestrator = BypassOrchestrator::new(config)?;
    let results = orchestrator.run().await?;

    for result in results {
        println!("{:?}: {}", result.bypass_type, if result.success { "OK" } else { "FAILED" });
    }

    // Direct iRa1n usage
    let mut ira1n = IRa1n::new(IRa1nConfig::default())?;
    let device_info = ira1n.get_device_info().await?;
    println!("Device: {} ({})", device_info.model, device_info.udid);

    // Direct iremovalpro.dll usage
    let iremoval = IremovalPro::new(None)?;
    let result = iremoval.action("", "info", "{}")?;
    println!("Info: {}", result);

    Ok(())
}
```

## Legal Notice

⚠️ **IMPORTANT**: This tool is for **educational and authorized testing purposes only**.

- Only use on devices you own or have explicit written permission to test
- Bypassing activation locks on devices you don't own may be illegal in your jurisdiction
- This tool uses the checkm8 bootrom exploit which is a hardware vulnerability
- The authors are not responsible for any misuse or damage caused by this tool

## Components Source

The native libraries used by this toolkit come from:
- **iRemoval PRO** - Commercial bypass tool (iremovalpro.dll)
- **iRa1n** - checkra1n-based open source tool (ira1n.dll, Data.dll)
- **libimobiledevice** - Open source iOS communication stack

Ensure you have legal rights to use these components.

## Development

### Building

```bash
# Development build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Generate shell completions
cargo run -- generate-completions
```

### Project Structure

```
ios-bypass-rs/
├── src/
│   ├── main.rs           # Entry point
│   ├── lib.rs            # Library exports
│   ├── error.rs          # Error types
│   ├── iremovalpro.rs    # iremovalpro.dll FFI bindings
│   ├── ira1n.rs          # iRa1n/checkra1n FFI bindings
│   ├── device.rs         # Device detection & management
│   ├── bypass.rs         # High-level bypass orchestration
│   ├── ramdisk.rs        # Ramdisk creation
│   └── cli.rs            # Command-line interface
├── build.rs              # Build script (native lib detection)
├── Cargo.toml
└── README.md
```

## Troubleshooting

### "Device not found"
- Ensure device is connected via USB
- Trust the computer on the device
- Install Apple Mobile Device Support (Windows)
- Run `ios-bypass doctor` to check components

### "DLL not found"
- Set environment variables:
  ```cmd
  set IREMOVALPRO_DLL_PATH=C:\path\to\iremovalpro.dll
  set IRA1N_DLL_PATH=C:\path\to\ira1n.dll
  set LIBIMOBILEDEVICE_DIR=C:\path\to\libimobiledevice\bin
  ```

### "Exploit failed"
- Device must be in DFU mode
- Only A5-A11 devices supported
- Try `--enter-dfu` flag first

### "Permission denied" (Linux)
```bash
sudo usermod -a -G plugdev $USER
# Log out and back in
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit PR

## License

MIT OR Apache-2.0

## Disclaimer

This software is provided "as is" without warranty. Use at your own risk.
The authors are not responsible for any damage, data loss, or legal issues
arising from the use of this tool.#   i o s - b y p a s s - r s  
 