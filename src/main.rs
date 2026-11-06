//! iOS Bypass Toolkit - Main entry point
//!
//! A Rust-based toolkit for iOS device bypass operations using checkm8 exploit.
//! Supports iCloud activation lock bypass, passcode bypass, MDM removal, and file system access.

use clap::CommandFactory;
use tracing::Level;

mod cli;
mod error;
mod iremovalpro;
mod ira1n;
mod device;
mod bypass;
mod ramdisk;

use crate::cli::run;
use crate::error::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize panic handler for better error messages
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("\n{}", "═".repeat(60).red());
        eprintln!("{}", "PANIC: Unexpected error occurred".red().bold());
        eprintln!("{}", "═".repeat(60).red());

        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            eprintln!("Message: {}", s);
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            eprintln!("Message: {}", s);
        } else {
            eprintln!("Message: Unknown panic payload");
        }

        if let Some(location) = panic_info.location() {
            eprintln!("Location: {}:{}:{}", location.file(), location.line(), location.column());
        }

        eprintln!("\n{}", "Please report this issue with the above information.".yellow());
        eprintln!("{}", "═".repeat(60).red());
    }));

    // Run CLI
    if let Err(e) = run().await {
        eprintln!("\n{} {}", "Error:".red().bold(), e);

        // Print error chain
        let mut source = e.source();
        while let Some(err) = source {
            eprintln!("  caused by: {}", err);
            source = err.source();
        }

        std::process::exit(1);
    }

    Ok(())
}

/// Generate shell completions (call during build)
pub fn generate_completions() -> Result<()> {
    use std::io::Write;

    let mut cmd = crate::cli::Cli::command();
    let name = cmd.get_name().to_string();

    // Generate for all supported shells
    let shells = [
        clap_complete::Shell::Bash,
        clap_complete::Shell::Zsh,
        clap_complete::Shell::Fish,
        clap_complete::Shell::PowerShell,
    ];

    for shell in shells {
        let mut buf = Vec::new();
        clap_complete::generate(shell, &mut cmd, &name, &mut buf);

        let ext = match shell {
            clap_complete::Shell::Bash => "bash",
            clap_complete::Shell::Zsh => "zsh",
            clap_complete::Shell::Fish => "fish",
            clap_complete::Shell::PowerShell => "ps1",
            _ => "txt",
        };

        let filename = format!("{}.{}", name, ext);
        std::fs::write(&filename, buf)?;
        println!("Generated completion: {}", filename);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main_compiles() {
        // Just verify the main function compiles
        assert!(true);
    }
}