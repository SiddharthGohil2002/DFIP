# Building DFIP Investigator

## Prerequisites

Install Node.js 20+ and Rust stable with Cargo. Tauri's platform prerequisites must also be installed for the target OS.

## Windows (the only supported desktop target)

Run `desktop/scripts/build-windows.ps1` from PowerShell. It produces MSI/NSIS installers under `desktop/src-tauri/target/release/bundle/`.

DFIP Investigator is currently built and distributed for Windows only. macOS and Linux are not built or tested targets.

## Native functions

The Tauri command bridge provides local hashing, non-overwriting evidence copy, read-only preservation, local case workspace creation/listing, directory inventory, forensic-tool discovery, and bounded allow-listed tool execution.

The desktop application should only advertise physical-device acquisition after the relevant OS-specific acquisition provider and hardware/write-blocker workflow has been validated.
