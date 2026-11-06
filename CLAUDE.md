# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ios-bypass-rs** is a Rust-based iOS bypass toolkit that uses the checkm8 bootrom exploit (A5-A11 devices, iPhone 4s through iPhone X) to perform various bypass operations:

- **iCloud Activation Lock Bypass** - Remove iCloud activation lock
- **Passcode Bypass** - Bypass device passcode
- **MDM Removal** - Remove Mobile Device Management enrollment
- **File System Access** - Access device filesystem via AFC/SSH

The project provides safe Rust FFI bindings for `iremovalpro.dll` and `ira1n.dll` native libraries, plus high-level orchestration for bypass operations.

## Build Commands

```bash
# Build the project
cargo build

# Build with all features (default includes FFI bindings)
cargo build --features "ffi-iremovallpro,ffi-libimobiledevice"

# Build release with optimizations
cargo build --release

# Run tests
cargo test

# Run a specific test
cargo test test_name

# Check code without building
cargo check

# Lint with clippy
cargo clippy -- -D warnings

# Format code
cargo fmt

# Generate shell completions (for distribution)
cargo run --bin ios-bypass -- --help  # Just to verify binary works
```

## Running the CLI

```bash
# Build and run
cargo run -- [COMMAND]

# Or build release first
cargo build --release
./target/release/ios-bypass [COMMAND]

# Common commands:
ios-bypass devices                    # List connected devices
ios-bypass devices --watch            # Monitor for device changes
ios-bypass info                       # Get device info
ios-bypass doctor                     # Check component availability
ios-bypass bypass --types all         # Full bypass (all types)
ios-bypass icloud                     # iCloud bypass only
ios-bypass passcode                   # Passcode bypass only
ios-bypass mdm                        # MDM removal only
ios-bypass file-access                # File access only
ios-bypass backup -o backup.img       # Create backup
ios-bypass restore -b backup.img      # Restore from backup
ios-bypass exploit                    # Run checkm8 exploit only
ios-bypass enter-recovery             # Enter recovery mode
ios-bypass exit-recovery              # Exit recovery mode
ios-bypass build-ramdisk -o ./out     # Build custom ramdisk
```

## Architecture

### Module Structure

```
src/
├── lib.rs           # Main library exports and prelude
├── main.rs          # CLI entry point
├── cli.rs           # Command-line interface (clap-based)
├── error.rs         # Error types and Result alias
├── device.rs        # Device detection, enumeration, info parsing
├── bypass.rs        # High-level bypass orchestration
├── ira1n.rs         # FFI bindings for iRa1n (checkra1n-based)
├── iremovalpro.rs   # FFI bindings for iremovalpro.dll
└── ramdisk.rs       # Custom ramdisk creation/management
```

### Key Components

1. **DeviceManager** (`device.rs`) - Scans for iOS devices via:
   - `libimobiledevice` (if available via dynamic loading)
   - `idevice_id` / `ideviceinfo` command-line tools (fallback)
   - `irecovery -q` for DFU/Recovery mode devices
   Parses device info including UDID, model, iOS version, chip ID, lock states, and determines supported bypass types based on hardware (checkm8 supports A5-A11).

2. **BypassOrchestrator** (`bypass.rs`) - Coordinates full bypass operations:
   - Validates device support for requested bypass types
   - Runs checkm8 exploit via iRa1n
   - Boots custom ramdisk with bypass tools
   - Executes bypass operations (iCloud, Passcode, MDM, FileAccess)
   - Progress callbacks with staged updates (Initializing → Detecting → Exploit → Ramdisk → Bypass → Complete)

3. **IRa1n** (`ira1n.rs`) - Wrapper for iRa1n components:
   - Loads `ira1n.dll` dynamically (FFI) or executes `iRa1n.exe` (CLI fallback)
   - Supports modes: ExploitOnly, FullBypass, Enter/Exit Recovery, Backup, Restore, Info
   - JSON-based communication with native library/CLI
   - Availability checking for all required components

4. **IremovalPro** (`iremovalpro.rs`) - FFI bindings for `iremovalpro.dll`:
   - Exports: `Action`, `SetCallbacks`, `SetWinInfo`, `DotNetRuntimeDebugHeader`
   - Callback system with typed `CallbackType` enum (Progress, Status, Error, Stage, DeviceChange, Log, InputRequest, Complete)
   - Builder pattern for configuration

5. **RamdiskBuilder** (`ramdisk.rs`) - Creates custom Linux ramdisks:
   - Directory structure creation (initramfs)
   - Adds SSH, AFC, bypass scripts
   - Compression: None, Gzip, LZ4, Zstd
   - Device-specific kernel selection

### Data Flow

```
CLI (cli.rs)
    │
    ├─→ DeviceManager.scan() ──→ DeviceInfo (UDID, model, iOS, chip, locks, state)
    │
    ├─→ BypassOrchestrator.run()
    │       │
    │       ├─→ IRa1n.full_bypass() ──→ ira1n.dll / iRa1n.exe
    │       │       │
    │       │       └─→ checkm8 exploit → custom ramdisk → bypass scripts
    │       │
    │       └─→ Progress callbacks (BypassProgress: stage, progress%, message)
    │
    └─→ Results: BypassResult (success, logs, backup_path, duration)
```

### Hardware Support Matrix

The toolkit only works on **checkm8-vulnerable devices (A5-A11)**:

| Chip | Devices | iOS Versions |
|------|---------|--------------|
| A5 (S5L8940/42/45/47) | iPhone 4S, iPad 2/3, iPod 5 | All |
| A6 (S5L8950/55) | iPhone 5, iPhone 5C | All |
| A7 (S5L8960) | iPhone 5S, iPad Air, iPad Mini 2/3 | All |
| A8 (S5L8965/70/75/76) | iPhone 6/6+, iPad Air 2, iPad Mini 4 | All |
| A9 (S5L8980/85) | iPhone 6S/6S+, SE 1st, iPad 2017 | All |
| A10 (S5L8990) | iPhone 7/7+, iPad 2018/2019 | All |
| A11 (T8010) | iPhone 8/8+, iPhone X | All |

**A12+ devices (iPhone XS and newer) are NOT supported.**

## Required External Dependencies

These native binaries must be available (searched in default locations or via env vars):

| Component | Purpose | Default Search Path |
|-----------|---------|---------------------|
| `iremovalpro.dll` | Main bypass engine | `./iremovalpro.dll`, `C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\iremovalpro.dll` |
| `ira1n.dll` | Checkra1n wrapper | `./ira1n.dll`, `C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\ref\ira1n\ira1n.dll` |
| `iRa1n.exe` | CLI fallback | `./iRa1n.exe`, same as above |
| `Data.dll` | iRa1n data | `C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\ref\ira1n\Data.dll` |
| `libimobiledevice-1.0.dll` | Device communication | `C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\ref\ira1n\bin\` |
| `libirecovery-1.0.dll` | DFU/Recovery | Same as above |
| `libplist-2.0.dll` | Property lists | Same as above |
| `libusbmuxd-2.0.dll` | USB multiplexing | Same as above |

**Command-line tools** (must be in PATH):
- `idevice_id`, `ideviceinfo` - device enumeration/info
- `irecovery` - DFU/Recovery interaction
- `iproxy` - USB port forwarding
- `ifuse` - AFC mounting

### Environment Variables

```bash
IREMOVALPRO_DLL_PATH=/path/to/iremovalpro.dll
IRA1N_DLL_PATH=/path/to/ira1n.dll
LIBIMOBILEDEVICE_DIR=/path/to/libimobiledevice/bin
```

## Development Workflow

### Adding New Bypass Types

1. Add variant to `BypassType` enum in `device.rs`
2. Add mapping in `BypassOrchestrator::execute_bypass()` to `IRa1nBypassType`
3. Add CLI command variant in `cli.rs` if needed
4. Update `DeviceManager::determine_supported_bypasses()` for hardware checks

### Adding New iRa1n Modes

1. Add variant to `IRa1nMode` enum in `ira1n.rs`
2. Add CLI argument mapping in `execute_cli()`
3. Add DLL parameter handling in `execute_dll()`
4. Add handler method on `IRa1n` struct

### Testing

```bash
# Run all tests
cargo test

# Run tests in specific module
cargo test device::
cargo test bypass::
cargo test ira1n::
cargo test iremovalpro::
cargo test ramdisk::

# Run with output
cargo test -- --nocapture
```

### Code Style

- Uses `tracing` for logging (debug, info, warn, error)
- Error handling via `thiserror` with `Error` enum and `Result<T>` alias
- Async runtime: `tokio` with full features
- FFI uses `libc` and `winapi` (Windows) for dynamic library loading
- Serialization: `serde` with JSON
- CLI: `clap` with derive feature

## Important Notes

### Legal/Ethical

This toolkit is for **educational and authorized testing purposes only**. Only use on devices you own or have explicit permission to test. The checkm8 exploit is a hardware vulnerability that cannot be patched via software updates.

### Windows-Specific

- Primary target platform is Windows (uses `winapi` for DLL loading)
- DLL search paths are hardcoded for the BFF tool directory structure
- Cross-platform support exists but is untested (Linux/macOS use `dlopen`)

### Limitations

- No pre-built ramdisks included - must provide custom or build your own
- `libimobiledevice` bindings are minimal (uses CLI tools as fallback)
- No automated ramdisk download - `RamdiskManager::download_ramdisk()` returns error
- Windows-only DLL paths in `build.rs` and source code

### Debugging

```bash
# Verbose logging
ios-bypass -v [command]

# Check component availability
ios-bypass doctor

# Run exploit only to verify checkm8 works
ios-bypass exploit --enter-dfu
```

## Common Issues

| Issue | Solution |
|-------|----------|
| "iremovalpro.dll not found" | Set `IREMOVALPRO_DLL_PATH` or place DLL in working directory |
| "ira1n.dll not found" | Set `IRA1N_DLL_PATH` or ensure BFF tool is installed |
| "libimobiledevice not found" | Set `LIBIMOBILEDEVICE_DIR` to bin folder with DLLs |
| Device not detected | Ensure `idevice_id`, `irecovery` in PATH; try DFU mode |
| "Unsupported device" | Only A5-A11 supported; check chip ID in `device.rs` |
| Permission denied | Run as Administrator (required for USB device access) |