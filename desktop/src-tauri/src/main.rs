#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::State;
use walkdir::WalkDir;

#[derive(Default)]
struct AppState {
    lock: Mutex<()>,
}

#[derive(Serialize)]
struct ToolInfo {
    name: String,
    path: Option<String>,
    available: bool,
    version: Option<String>,
    hint: String,
}

fn truncate_utf8_safe(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[derive(Serialize)]
struct HashResult {
    algorithm: String,
    sha256: String,
    sha512: String,
    bytes: u64,
    elapsed_ms: u128,
}

#[derive(Serialize)]
struct CopyResult {
    source: String,
    destination: String,
    sha256: String,
    sha512: String,
    bytes: u64,
    readonly: bool,
    elapsed_ms: u128,
}

#[derive(Serialize)]
struct FileEntry {
    path: String,
    size: u64,
    modified: u64,
    is_dir: bool,
}

#[derive(Deserialize)]
struct ToolRequest {
    tool: String,
    args: Vec<String>,
    timeout_seconds: Option<u64>,
}

fn allowed_tool(name: &str) -> bool {
    matches!(
        name,
        "fls" | "istat" | "fsstat" | "mmls" | "icat" | "exiftool" | "tshark" | "yara" | "vol" | "strings" | "file"
    )
}

fn tool_hint(name: &str) -> &'static str {
    match name {
        "fls" | "istat" | "fsstat" | "mmls" | "icat" => "Install The Sleuth Kit (TSK) from sleuthkit.org or run 'choco install sleuthkit'",
        "exiftool" => "Install ExifTool from exiftool.org or run 'choco install exiftool'",
        "tshark" => "Install Wireshark (includes TShark) from wireshark.org or run 'choco install wireshark'",
        "yara" => "Install YARA from github.com/VirusTotal/yara/releases or run 'choco install yara'",
        "vol" => "Install Volatility 3 via 'pip install volatility3'",
        "strings" => "Install GNU strings (binutils) or Sysinternals strings.exe",
        "file" => "Install file utility for Windows",
        _ => "Tool available on system PATH",
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn hash_reader(mut f: File) -> Result<HashResult, String> {
    let start = Instant::now();
    let mut h256 = Sha256::new();
    let mut h512 = Sha512::new();
    let mut buf = [0u8; 1024 * 1024];
    let mut n = 0u64;
    loop {
        let r = f.read(&mut buf).map_err(|e| e.to_string())?;
        if r == 0 {
            break;
        }
        h256.update(&buf[..r]);
        h512.update(&buf[..r]);
        n += r as u64;
    }
    Ok(HashResult {
        algorithm: "SHA-256 + SHA-512".into(),
        sha256: hex::encode(h256.finalize()),
        sha512: hex::encode(h512.finalize()),
        bytes: n,
        elapsed_ms: start.elapsed().as_millis(),
    })
}

#[tauri::command]
fn system_info() -> serde_json::Value {
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "DFIP-WORKSTATION".into());
    let cores = std::env::var("NUMBER_OF_PROCESSORS").unwrap_or_else(|_| "4".into());
    serde_json::json!({
        "app": "DFIP Investigator",
        "version": "2.0.0",
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "hostname": hostname,
        "cpu_cores": cores,
        "timestamp": now()
    })
}

#[tauri::command]
fn hash_file(path: String, state: State<AppState>) -> Result<HashResult, String> {
    let _g = state.lock.lock().map_err(|_| "lock poisoned".to_string())?;
    hash_reader(File::open(&path).map_err(|e| format!("Cannot open file '{}': {}", path, e))?)
}

#[tauri::command]
fn copy_evidence(source: String, destination: String, state: State<AppState>) -> Result<CopyResult, String> {
    let _g = state.lock.lock().map_err(|_| "lock poisoned".to_string())?;
    let start = Instant::now();
    let src = Path::new(&source);
    if !src.is_file() {
        return Err("Source evidence is not a regular file".into());
    }
    let dst = PathBuf::from(&destination);
    if dst.exists() {
        return Err("Refusing to overwrite an existing evidence destination".into());
    }
    if let Some(p) = dst.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let mut input = File::open(src).map_err(|e| e.to_string())?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&dst)
        .map_err(|e| e.to_string())?;
    let mut h256 = Sha256::new();
    let mut h512 = Sha512::new();
    let mut buf = [0u8; 1024 * 1024];
    let mut n = 0u64;
    loop {
        let r = input.read(&mut buf).map_err(|e| e.to_string())?;
        if r == 0 {
            break;
        }
        output.write_all(&buf[..r]).map_err(|e| e.to_string())?;
        h256.update(&buf[..r]);
        h512.update(&buf[..r]);
        n += r as u64;
    }
    output.sync_all().map_err(|e| e.to_string())?;
    drop(output);
    let mut perms = fs::metadata(&dst).map_err(|e| e.to_string())?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(&dst, perms).map_err(|e| e.to_string())?;
    Ok(CopyResult {
        source,
        destination: dst.to_string_lossy().into(),
        sha256: hex::encode(h256.finalize()),
        sha512: hex::encode(h512.finalize()),
        bytes: n,
        readonly: true,
        elapsed_ms: start.elapsed().as_millis(),
    })
}

#[tauri::command]
fn list_directory(path: String, recursive: bool) -> Result<Vec<FileEntry>, String> {
    let p = Path::new(&path);
    if !p.is_dir() {
        return Err("Not a directory".into());
    }
    let it = if recursive {
        WalkDir::new(p)
            .into_iter()
            .filter_map(Result::ok)
            .map(|e| e.path().to_path_buf())
            .collect::<Vec<_>>()
    } else {
        fs::read_dir(p)
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect()
    };
    let mut out = Vec::new();
    for x in it {
        if let Ok(m) = fs::metadata(&x) {
            out.push(FileEntry {
                path: x.to_string_lossy().into(),
                size: if m.is_file() { m.len() } else { 0 },
                modified: m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                is_dir: m.is_dir(),
            });
        }
    }
    Ok(out)
}

#[tauri::command]
fn tool_inventory() -> Vec<ToolInfo> {
    let tools = [
        "fls", "istat", "fsstat", "mmls", "icat", "exiftool", "tshark", "yara", "vol", "strings", "file",
    ];
    tools
        .iter()
        .map(|n| {
            let p = which::which(n).ok();
            let mut version = None;
            if let Some(ref bin_path) = p {
                let ver_res = Command::new(bin_path).arg("-V").output().or_else(|_| {
                    Command::new(bin_path).arg("--version").output()
                });
                if let Ok(out) = ver_res {
                    let s = String::from_utf8_lossy(&out.stdout);
                    if let Some(first_line) = s.lines().next() {
                        if !first_line.trim().is_empty() {
                            version = Some(first_line.trim().to_string());
                        }
                    }
                }
            }
            ToolInfo {
                name: n.to_string(),
                path: p.as_ref().map(|x| x.to_string_lossy().into()),
                available: p.is_some(),
                version,
                hint: tool_hint(n).to_string(),
            }
        })
        .collect()
}

#[tauri::command]
fn run_forensic_tool(req: ToolRequest) -> Result<serde_json::Value, String> {
    if !allowed_tool(&req.tool) {
        return Err("Tool is not on the DFIP allow-list".into());
    }
    let path = which::which(&req.tool).map_err(|_| format!("Tool unavailable: {}", req.tool))?;
    let timeout = Duration::from_secs(req.timeout_seconds.unwrap_or(60).min(900));
    let mut child = Command::new(path)
        .args(&req.args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let start = Instant::now();
    loop {
        if let Some(_status) = child.try_wait().map_err(|e| e.to_string())? {
            break;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(serde_json::json!({
                "tool": req.tool,
                "success": false,
                "timed_out": true,
                "timeout_seconds": timeout.as_secs(),
                "duration_ms": start.elapsed().as_millis()
            }));
        }
        thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let limit = 2 * 1024 * 1024;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    Ok(serde_json::json!({
        "tool": req.tool,
        "success": out.status.success(),
        "code": out.status.code(),
        "stdout": truncate_utf8_safe(&stdout, limit),
        "stderr": truncate_utf8_safe(&stderr, limit),
        "timed_out": false,
        "duration_ms": start.elapsed().as_millis(),
        "timeout_seconds": timeout.as_secs()
    }))
}

#[tauri::command]
fn set_readonly(path: String) -> Result<bool, String> {
    let mut p = fs::metadata(&path).map_err(|e| e.to_string())?.permissions();
    perms_readonly(&mut p);
    fs::set_permissions(&path, p).map_err(|e| e.to_string())?;
    Ok(true)
}

fn perms_readonly(perms: &mut fs::Permissions) {
    perms.set_readonly(true);
}

#[tauri::command]
fn app_data_dir() -> Result<String, String> {
    let p = dirs_next::data_dir().ok_or("No platform data directory")?;
    let root = p.join("DFIP");
    // Ensure standard DFIP local directories exist
    let _ = fs::create_dir_all(root.join("cases"));
    let _ = fs::create_dir_all(root.join("cache"));
    let _ = fs::create_dir_all(root.join("config"));
    let _ = fs::create_dir_all(root.join("temp"));
    Ok(root.to_string_lossy().into())
}

#[tauri::command]
fn create_local_case(name: String) -> Result<serde_json::Value, String> {
    let base = dirs_next::data_dir().ok_or("No platform data directory")?.join("DFIP");
    let root = base.join("cases");
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let _ = fs::create_dir_all(base.join("cache"));
    let _ = fs::create_dir_all(base.join("config"));
    let _ = fs::create_dir_all(base.join("temp"));

    let id = format!(
        "LOCAL-{}-{}",
        now(),
        name.chars().filter(|c| c.is_ascii_alphanumeric()).take(18).collect::<String>()
    );
    let dir = root.join(&id);
    fs::create_dir_all(dir.join("evidence")).map_err(|e| e.to_string())?;
    fs::create_dir_all(dir.join("analysis")).map_err(|e| e.to_string())?;
    fs::create_dir_all(dir.join("artifacts")).map_err(|e| e.to_string())?;
    fs::create_dir_all(dir.join("reports")).map_err(|e| e.to_string())?;
    fs::create_dir_all(dir.join("logs")).map_err(|e| e.to_string())?;

    let manifest = serde_json::json!({
        "case_id": id,
        "name": name,
        "created_at": now(),
        "mode": "OFFLINE_READY",
        "workspace_path": dir.to_string_lossy()
    });
    fs::write(dir.join("case.json"), serde_json::to_vec_pretty(&manifest).unwrap())
        .map_err(|e| e.to_string())?;
    Ok(manifest)
}

#[tauri::command]
fn list_local_cases() -> Result<Vec<serde_json::Value>, String> {
    let root = dirs_next::data_dir().ok_or("No platform data directory")?.join("DFIP").join("cases");
    if !root.exists() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    for e in fs::read_dir(root).map_err(|e| e.to_string())? {
        let p = e.map_err(|e| e.to_string())?.path().join("case.json");
        if p.is_file() {
            if let Ok(b) = fs::read(&p) {
                if let Ok(v) = serde_json::from_slice(&b) {
                    out.push(v);
                }
            }
        }
    }
    Ok(out)
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            system_info,
            hash_file,
            copy_evidence,
            list_directory,
            tool_inventory,
            run_forensic_tool,
            set_readonly,
            app_data_dir,
            create_local_case,
            list_local_cases
        ])
        .run(tauri::generate_context!())
        .expect("error while running DFIP Investigator");
}
