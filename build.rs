//! Build script for ios-bypass-rs
//!
//! Handles native library detection and linking for Windows.

use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to re-run if these files change
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=IREMOVALPRO_DLL_PATH");
    println!("cargo:rerun-if-env-changed=IRA1N_DLL_PATH");
    println!("cargo:rerun-if-env-changed=LIBIMOBILEDEVICE_DIR");

    #[cfg(target_os = "windows")]
    {
        // Link Windows libraries
        println!("cargo:rustc-link-lib=kernel32");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=iphlpapi");
        println!("cargo:rustc-link-lib=ncrypt");
        println!("cargo:rustc-link-lib=ole32");
        println!("cargo:rustc-link-lib=ws2_32");

        // Try to find iremovalpro.dll
        if let Ok(path) = env::var("IREMOVALPRO_DLL_PATH") {
            println!("cargo:rustc-env=IREMOVALPRO_DLL_PATH={}", path);
            println!("cargo:rerun-if-changed={}", path);
        } else {
            // Search common locations
            let search_paths = [
                "iremovalpro.dll",
                r"C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\iremovalpro.dll",
            ];

            for path in &search_paths {
                if std::path::Path::new(path).exists() {
                    println!("cargo:rustc-env=IREMOVALPRO_DLL_PATH={}", path);
                    println!("cargo:rerun-if-changed={}", path);
                    break;
                }
            }
        }

        // Try to find ira1n.dll
        if let Ok(path) = env::var("IRA1N_DLL_PATH") {
            println!("cargo:rustc-env=IRA1N_DLL_PATH={}", path);
            println!("cargo:rerun-if-changed={}", path);
        } else {
            let search_paths = [
                "ira1n.dll",
                r"C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\ref\ira1n\ira1n.dll",
            ];

            for path in &search_paths {
                if std::path::Path::new(path).exists() {
                    println!("cargo:rustc-env=IRA1N_DLL_PATH={}", path);
                    println!("cargo:rerun-if-changed={}", path);
                    break;
                }
            }
        }

        // Try to find libimobiledevice stack
        if let Ok(dir) = env::var("LIBIMOBILEDEVICE_DIR") {
            println!("cargo:rustc-env=LIBIMOBILEDEVICE_DIR={}", dir);
            println!("cargo:rerun-if-changed={}", dir);
        } else {
            let default_dir = PathBuf::from(r"C:\Users\Lintang\Downloads\[BFF]Jailbreak&Ramdisk_Bypass_Tool\ref\ira1n\bin");
            if default_dir.exists() {
                println!("cargo:rustc-env=LIBIMOBILEDEVICE_DIR={}", default_dir.display());
                println!("cargo:rerun-if-changed={}", default_dir.display());
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Link Linux libraries
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=imobiledevice");
        println!("cargo:rustc-link-lib=irecovery");
        println!("cargo:rustc-link-lib=plist-2.0");
        println!("cargo:rustc-link-lib=usbmuxd-2.0");
        println!("cargo:rustc-link-lib=usb-1.0");
    }

    #[cfg(target_os = "macos")]
    {
        // Link macOS frameworks
        println!("cargo:rustc-link-lib=framework=IOKit");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=imobiledevice");
        println!("cargo:rustc-link-lib=irecovery");
        println!("cargo:rustc-link-lib=plist-2.0");
        println!("cargo:rustc-link-lib=usbmuxd-2.0");
    }

    // Generate compile-time constants
    println!("cargo:rustc-env=CARGO_PKG_VERSION={}", env::var("CARGO_PKG_VERSION").unwrap_or_default());
    println!("cargo:rustc-env=GIT_HASH={}", get_git_hash().unwrap_or_default());
}

fn get_git_hash() -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
}