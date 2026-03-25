//! Blob shim — tiny launcher that reads a target exe path appended to itself,
//! then launches it with the original arguments, waits, and propagates the exit code.
//!
//! Binary format: [PE image][target path as UTF-8][u32 LE: path length]
//!
//! To create a shim: concatenate this exe + target path bytes + (path.len() as u32).to_le_bytes()

use std::process;

fn run() -> Result<i32, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find own exe: {e}"))?;
    let data = std::fs::read(&exe).map_err(|e| format!("cannot read own exe: {e}"))?;

    if data.len() < 4 {
        return Err("shim binary too small".to_string());
    }

    // Read the path length from the last 4 bytes
    let len_bytes: [u8; 4] = data[data.len() - 4..].try_into().unwrap();
    let path_len = u32::from_le_bytes(len_bytes) as usize;

    if path_len == 0 || path_len > 32768 || data.len() < 4 + path_len {
        return Err("no target path appended to shim (use blob to create shims)".to_string());
    }

    let path_bytes = &data[data.len() - 4 - path_len..data.len() - 4];
    let target = std::str::from_utf8(path_bytes).map_err(|e| format!("invalid target path: {e}"))?;

    let status = process::Command::new(target)
        .args(std::env::args_os().skip(1))
        .status()
        .map_err(|e| format!("failed to launch {target}: {e}"))?;

    Ok(status.code().unwrap_or(1))
}

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(msg) => {
            eprintln!("blob-shim: {msg}");
            process::exit(127);
        }
    }
}
