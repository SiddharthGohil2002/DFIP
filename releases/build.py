import os
import sys
import subprocess
import hashlib
import zipfile
import shutil
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELEASES_DIR = os.path.join(ROOT, "releases")
STORAGE_DIR = os.path.join(ROOT, "storage", "downloads")
FRONTEND_PUBLIC_DIR = os.path.join(ROOT, "frontend", "public", "downloads")
FRONTEND_DIST_DIR = os.path.join(ROOT, "frontend", "dist", "downloads")
DESKTOP_PUBLIC_DIR = os.path.join(ROOT, "desktop", "ui", "public", "downloads")
DESKTOP_DIST_DIR = os.path.join(ROOT, "desktop", "ui", "dist", "downloads")

def compute_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()

def main():
    print("[*] DFIP Release Package Builder v2.0.0 starting...")
    
    csc_paths = [
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    ]
    csc = next((p for p in csc_paths if os.path.exists(p)), None)
    if not csc:
        print("[!] ERROR: csc.exe compiler not found in standard .NET paths.")
        sys.exit(1)
        
    launcher_cs = os.path.join(RELEASES_DIR, "Launcher.cs")
    exe_out = os.path.join(RELEASES_DIR, "DFIP-Investigator-Windows-x64.exe")
    zip_out = os.path.join(RELEASES_DIR, "DFIP-Investigator-v1.0.0-Windows-x64.zip")
    bat_file = os.path.join(RELEASES_DIR, "Launch-DFIP-Desktop.bat")
    cmd_file = os.path.join(RELEASES_DIR, "DFIP-Investigator.cmd")
    readme_file = os.path.join(RELEASES_DIR, "README.md")

    print(f"[*] Compiling {launcher_cs} -> {exe_out}...")
    compile_cmd = [
        csc,
        "/target:winexe",
        f"/out:{exe_out}",
        "/reference:System.Windows.Forms.dll,System.Drawing.dll",
        "/optimize+",
        launcher_cs
    ]
    res = subprocess.run(compile_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] Compilation failed:\n{res.stderr}\n{res.stdout}")
        sys.exit(res.returncode)
    print(f"[+] Compilation SUCCESSFUL: {exe_out}")

    exe_size = os.path.getsize(exe_out)
    exe_sha = compute_sha256(exe_out)
    print(f"    EXE Size: {exe_size} bytes")
    print(f"    EXE SHA-256: {exe_sha}")

    print(f"[*] Packaging portable archive: {zip_out}...")
    with zipfile.ZipFile(zip_out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(exe_out, "DFIP-Investigator-Windows-x64.exe")
        if os.path.exists(bat_file):
            zf.write(bat_file, "Launch-DFIP-Desktop.bat")
        if os.path.exists(cmd_file):
            zf.write(cmd_file, "DFIP-Investigator.cmd")
        if os.path.exists(readme_file):
            zf.write(readme_file, "README.md")
    
    zip_size = os.path.getsize(zip_out)
    zip_sha = compute_sha256(zip_out)
    print(f"[+] ZIP Package SUCCESSFUL: {zip_out}")
    print(f"    ZIP Size: {zip_size} bytes")
    print(f"    ZIP SHA-256: {zip_sha}")

    target_dirs = [
        FRONTEND_PUBLIC_DIR,
        FRONTEND_DIST_DIR,
        DESKTOP_PUBLIC_DIR,
        DESKTOP_DIST_DIR,
        STORAGE_DIR
    ]

    for d in target_dirs:
        os.makedirs(d, exist_ok=True)
        shutil.copy2(exe_out, os.path.join(d, "DFIP-Investigator-Windows-x64.exe"))
        shutil.copy2(zip_out, os.path.join(d, "DFIP-Investigator-v1.0.0-Windows-x64.zip"))
        if os.path.exists(bat_file):
            shutil.copy2(bat_file, os.path.join(d, "Launch-DFIP-Desktop.bat"))
        print(f"[+] Distributed artifacts to: {d}")

    # Synchronize SHA-256 hashes into backend/app/api/desktop.py
    desktop_py = os.path.join(ROOT, "backend", "app", "api", "desktop.py")
    if os.path.exists(desktop_py):
        with open(desktop_py, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Replace SHA256 in desktop.py
        # Installer sha256
        content = re.sub(
            r"('sha256':\s*')[A-Fa-f0-9]{64}(')",
            rf"\g<1>{exe_sha}\g<2>",
            content,
            count=1
        )
        # Portable sha256
        content = re.sub(
            r"('portable':\s*\{[^}]+'sha256':\s*')[A-Fa-f0-9]{64}(')",
            rf"\g<1>{zip_sha}\g<2>",
            content,
            count=1
        )
        # Response headers
        content = re.sub(
            r"(filename='DFIP-Investigator-Windows-x64\.exe'[\s\S]*?'X-DFIP-SHA256':\s*')[A-Fa-f0-9]{64}(')",
            rf"\g<1>{exe_sha}\g<2>",
            content,
            count=1
        )
        content = re.sub(
            r"(filename='DFIP-Investigator-v1\.0\.0-Windows-x64\.zip'[\s\S]*?'X-DFIP-SHA256':\s*')[A-Fa-f0-9]{64}(')",
            rf"\g<1>{zip_sha}\g<2>",
            content,
            count=1
        )
        with open(desktop_py, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Synchronized SHA-256 hashes in {desktop_py}")

    # Synchronize SHA-256 into frontend/src/pages/Public.tsx
    frontend_public_tsx = os.path.join(ROOT, "frontend", "src", "pages", "Public.tsx")
    if os.path.exists(frontend_public_tsx):
        with open(frontend_public_tsx, "r", encoding="utf-8") as f:
            f_content = f.read()
        f_content = re.sub(
            r"const sha256Hash = '[A-Fa-f0-9]{64}';",
            f"const sha256Hash = '{exe_sha}';",
            f_content
        )
        with open(frontend_public_tsx, "w", encoding="utf-8") as f:
            f.write(f_content)
        print(f"[+] Synchronized SHA-256 in {frontend_public_tsx}")

    # Synchronize SHA-256 into desktop/ui/src/pages/Public.tsx
    desktop_public_tsx = os.path.join(ROOT, "desktop", "ui", "src", "pages", "Public.tsx")
    if os.path.exists(desktop_public_tsx):
        with open(desktop_public_tsx, "r", encoding="utf-8") as f:
            d_content = f.read()
        d_content = re.sub(
            r"const sha256Hash = '[A-Fa-f0-9]{64}';",
            f"const sha256Hash = '{exe_sha}';",
            d_content
        )
        with open(desktop_public_tsx, "w", encoding="utf-8") as f:
            f.write(d_content)
        print(f"[+] Synchronized SHA-256 in {desktop_public_tsx}")

    print("\n[OK] BUILD COMPLETE! All download links, binaries, and checksums are fully up to date.")

if __name__ == "__main__":
    main()
