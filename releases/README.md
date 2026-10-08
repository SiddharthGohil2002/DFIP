# DFIP release artifacts

Desktop installers are built with `desktop/scripts/build-windows.ps1` and published by copying them to the server's `storage/downloads` folder (`-Publish` does this). The website then offers them with the SHA-256 computed from the file.

Do not commit installers to this repository. Sign them (Tauri `bundle.windows.certificateThumbprint`) before distributing outside a test environment.
