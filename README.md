# ios-bypass-rs

**Experimental Rust toolkit for iOS device inspection and authorized recovery research.**

`ios-bypass-rs` is a Rust codebase for exploring USB-connected iOS device communication, device metadata, recovery-state handling, backup workflows, and native-library interoperability. It is an experimental project, not an Apple product and not a production-ready repair utility.

> [!IMPORTANT]
> This repository contains experimental native FFI integrations and reverse-engineering research. It is **not** an Activation Lock removal service, passcode-cracking tool, MDM circumvention utility, or a substitute for Apple's supported recovery and account-recovery processes. Do not use it to defeat device security, access another person's data, or alter a device without the owner's informed authorization.
>
> The current source tree includes legacy code and interfaces whose names refer to bypass operations. Their presence does not mean those operations are implemented, reliable, safe, or supported. This README intentionally documents only legitimate inspection and recovery-oriented project context.

## Project status


- **Status:** Experimental / under active development.
- **Language:** Rust (2021 edition).
- **Primary development environment:** Windows 10/11 x64.
- **Other targets:** Linux and macOS conditionally referenced by the build script; they are not verified release targets.
- **Native dependencies:** Optional or platform-specific iOS communication libraries and FFI components.
- **Stability:** APIs and build requirements may change. No production-readiness or device-compatibility guarantee is made.

## What is in the repository

| Path | Purpose |
| --- | --- |
| `src/main.rs` | CLI application entry point |
| `src/lib.rs` | Library modules and public exports |
| `src/cli.rs` | Command-line parsing and command dispatch |
| `src/device.rs` | Device metadata, connection state, and device enumeration abstractions |
| `src/error.rs` | Shared error and result types |
| `src/iremovalpro.rs` | Native-library FFI wrapper |
| `src/ira1n.rs` | Native-library integration layer |
| `src/ira1n_corrected.rs` | Experimental corrected FFI declarations |
| `src/bypass.rs` | Legacy experimental orchestration code; not documented as a supported user workflow |
| `src/ramdisk.rs` | Experimental ramdisk construction and cache abstractions |
| `ffi/` | FFI-related source and declarations |
| `libs/` | Native library/support files used by the project |
| `build.rs` | Platform-specific native library detection and linker configuration |
| `Cargo.toml` / `Cargo.lock` | Rust package metadata and locked dependencies |
| `REVERSE_ENGINEERING_FINDINGS.md` | Static-analysis notes about third-party native components |

The repository may contain components that are proprietary or subject to separate licenses. Review their provenance and license terms before redistribution. Do not assume that a binary in `libs/` is covered by this repository's Rust source license.

## Intended safe scope

The project is being organized around legitimate, owner-authorized workflows such as:

- Enumerating an iOS device connected to the host.
- Reading device identifiers and reported software/hardware metadata where the connected-device interface permits it.
- Reporting connection and recovery-state information.
- Supporting user-authorized backup and restore research, with clear warnings about data-loss risk.
- Diagnosing missing host dependencies and native-library loading errors.
- Studying Rust FFI boundaries and error handling.

A feature should be treated as **experimental** until it has tests, documented prerequisites, safe failure behavior, and verification on supported hardware.

## Requirements

### General

- Rust toolchain with Cargo (Rust 2021 edition).
- Git.
- A supported host operating system and USB connection.
- An iOS device that you own or are explicitly authorized to service.

### Windows

- Windows 10 or Windows 11, x64.
- Apple device drivers / Apple Mobile Device support appropriate to the installed Apple software.
- Any native libraries required by the selected build configuration.
- A compatible MSVC C/C++ build toolchain may be required by native dependencies.

### Linux and macOS

The build script contains conditional linker configuration for these platforms, but platform support has not been established by a published CI matrix. Install the corresponding system development packages only after checking the requirements of the specific native dependency you intend to build.

## Build and inspect

Clone the repository:

```bash
git clone https://github.com/Strong-Bee/ios-bypass-rs.git
cd ios-bypass-rs
```

Check formatting and compile the Rust project:

```bash
cargo fmt --all -- --check
cargo check
```

Run the test suite:

```bash
cargo test
```

Build an optimized binary:

```bash
cargo build --release
```

These commands validate only the code paths and dependencies available in your environment. A successful build does not prove that a connected-device workflow is safe, complete, or compatible with a particular iPhone or iPad.

## Native libraries and FFI

Some modules dynamically load native libraries and/or expect platform-specific libraries at build or runtime. The build script recognizes environment variables including:

- `IREMOVALPRO_DLL_PATH`
- `IRA1N_DLL_PATH`
- `LIBIMOBILEDEVICE_DIR`

These variables are implementation details for experimental FFI integration, **not a recommendation to obtain or run third-party binaries**. Use only components you are legally entitled to use, from sources you trust, and verify their integrity. Do not commit proprietary DLLs, signing material, credentials, device backups, or other private data to this repository.

## Data safety

Before any operation that could modify a device:

1. Confirm that you own the device or have explicit authorization from its owner.
2. Make a verified backup using an official, supported workflow where possible.
3. Confirm that the backup can be accessed and that you understand the restore implications.
4. Keep personal data and device identifiers out of issue reports and public logs.
5. Stop if the tool reports an unexpected state or an unsupported device.

For Activation Lock, Apple Account, passcode, or organizational enrollment problems, use the account owner, the managing organization, or Apple's official support and recovery procedures. This project does not provide a way around those protections.

## Development notes

- Keep unsafe Rust and FFI code isolated and documented.
- Validate pointers, buffer sizes, string encodings, calling conventions, and native return codes at every FFI boundary.
- Avoid hard-coded developer-specific filesystem paths.
- Do not claim support for a device or iOS version without reproducible tests.
- Add automated tests for parsing, error handling, and platform-independent logic.
- Keep proprietary or externally licensed components separate from redistributable source.

## Contributing

Contributions are welcome for safe device enumeration, metadata parsing, diagnostics, documentation, portability, tests, and memory-safe FFI improvements.

1. Open an issue describing the bug or proposed change.
2. Create a focused feature branch.
3. Include tests and reproduction details where possible.
4. Document platform and dependency requirements.
5. Submit a pull request for review.

Do not submit changes intended to defeat Activation Lock, extract protected user data, crack passcodes, or evade organizational device management.

## License

The Rust package declares **MIT OR Apache-2.0** in `Cargo.toml`. This declaration does not automatically apply to third-party libraries, DLLs, firmware, payloads, or other assets in the repository. Check each component's license and redistribution terms separately.

## Disclaimer

This is an experimental, community-maintained software project provided "as is", without warranties or guarantees. Device operations can cause data loss or render a device unusable. The maintainers are not affiliated with or endorsed by Apple. Use supported Apple recovery procedures for real-world device servicing.
