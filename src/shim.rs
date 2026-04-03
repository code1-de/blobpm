//! Shim creation for Windows — embeds a tiny launcher exe with an appended relative target path.
//! The shim resolves the target path relative to its own directory at runtime.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

/// The embedded shim binary (console subsystem, 64-bit).
const SHIM_CLI: &[u8] = include_bytes!("../shim/bin/shim-cli.exe");

/// PE subsystem offset for PE32+ (64-bit): PE header offset + 0x5C.
const PE_SUBSYSTEM_OFFSET: usize = 0x5C;

/// `IMAGE_SUBSYSTEM_WINDOWS_GUI` = 2
const SUBSYSTEM_GUI: u16 = 2;

/// Create shim executables for all links in the manifest.
/// Returns a map of link dest paths → absolute shim file paths (for tracking in db).
pub fn create_shims(
    links: &BTreeMap<String, String>,
    config: &crate::client::Config,
) -> io::Result<BTreeMap<String, PathBuf>> {
    let mut created = BTreeMap::new();

    for (dest, target) in links {
        crate::client::validate_manifest_path(dest, target, "link")?;
        let dest_path = config.resolve_dest(dest);
        let target_path = config.resolve_dest(target);

        // Prevent self-links (compare resolved paths to catch ../x/../x tricks)
        if dest_path == target_path {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Link points to itself: {dest}")));
        }

        // Compute relative path from shim directory to target
        let shim_dir = dest_path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid link dest: {dest}")))?;
        fs::create_dir_all(shim_dir)?;

        let rel_path = pathdiff(shim_dir, &target_path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Cannot compute relative path from {dest} to {target} (different drives?)"),
            )
        })?;
        let rel_str = rel_path.to_string_lossy();

        // Detect GUI subsystem from target if it exists
        let gui = target_path.is_file() && is_gui_exe(&target_path);

        // Build shim: [PE binary][relative path UTF-8][u32 LE path length]
        let path_bytes = rel_str.as_bytes();
        let mut shim_data = Vec::with_capacity(SHIM_CLI.len() + path_bytes.len() + 4);
        shim_data.extend_from_slice(SHIM_CLI);

        // Patch PE subsystem if GUI
        if gui {
            let pe_offset = u32::from_le_bytes(shim_data[0x3C..0x40].try_into().unwrap()) as usize;
            let subsystem_addr = pe_offset + PE_SUBSYSTEM_OFFSET;
            if subsystem_addr + 2 <= shim_data.len() {
                shim_data[subsystem_addr..subsystem_addr + 2].copy_from_slice(&SUBSYSTEM_GUI.to_le_bytes());
            }
        }

        shim_data.extend_from_slice(path_bytes);
        #[allow(clippy::cast_possible_truncation)] // path_len validated <= 32768
        shim_data.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());

        fs::write(&dest_path, &shim_data)?;
        println!("  {dest} -> {} (shim{})", dest_path.display(), if gui { ", gui" } else { "" });

        created.insert(dest.clone(), dest_path);
    }

    Ok(created)
}

/// Check if a PE file has GUI subsystem.
fn is_gui_exe(path: &Path) -> bool {
    let Ok(data) = fs::read(path) else { return false };
    if data.len() < 0x40 {
        return false;
    }
    let pe_offset = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    let subsystem_addr = pe_offset + PE_SUBSYSTEM_OFFSET;
    if subsystem_addr + 2 > data.len() {
        return false;
    }
    let subsystem = u16::from_le_bytes(data[subsystem_addr..subsystem_addr + 2].try_into().unwrap());
    subsystem == SUBSYSTEM_GUI
}

/// Compute relative path from `base` to `target`. Returns None if on different drive roots.
fn pathdiff(base: &Path, target: &Path) -> Option<PathBuf> {
    // Try to use absolute paths
    let base = dunce::canonicalize(base).ok()?;
    let target_dir = target.parent()?;
    let target_file = target.file_name()?;

    // If target dir doesn't exist yet, work with what we have
    let target_dir_abs = dunce::canonicalize(target_dir).unwrap_or_else(|_| target_dir.to_path_buf());

    let base_parts: Vec<_> = base.components().collect();
    let target_parts: Vec<_> = target_dir_abs.components().collect();

    // Must share the same root (drive letter on Windows)
    if base_parts.first() != target_parts.first() {
        return None;
    }

    // Find common prefix length
    let common = base_parts.iter().zip(target_parts.iter()).take_while(|(a, b)| a == b).count();

    let mut rel = PathBuf::new();
    // Go up from base to common ancestor
    for _ in common..base_parts.len() {
        rel.push("..");
    }
    // Go down from common ancestor to target dir
    for part in &target_parts[common..] {
        rel.push(part);
    }
    // Append filename
    rel.push(target_file);

    Some(rel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_config(base_dir: &Path) -> crate::client::Config {
        crate::client::Config {
            server_url: String::new(),
            base_dir: base_dir.to_path_buf(),
            username: String::new(),
            password: String::new(),
            server_fingerprint: String::new(),
            cache_days: 0,
            path_map: BTreeMap::new(),
            cache_dir: None,
        }
    }

    #[test]
    fn create_shim_with_relative_path() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        // Create a fake target exe
        let target_dir = base.join("app").join("bin");
        fs::create_dir_all(&target_dir).unwrap();
        let target = target_dir.join("tool.exe");
        fs::write(&target, b"MZ fake exe").unwrap();

        // Create shim bin dir
        let shim_dir = base.join("bin");
        fs::create_dir_all(&shim_dir).unwrap();

        let mut links = BTreeMap::new();
        links.insert("bin/tool.exe".to_string(), "app/bin/tool.exe".to_string());

        let config = test_config(base);
        let created = create_shims(&links, &config).unwrap();

        // Shim file should exist
        let shim_path = &created["bin/tool.exe"];
        assert!(shim_path.is_file(), "shim not created: {}", shim_path.display());

        // Shim should be larger than the base shim (has appended path)
        let shim_size = fs::metadata(shim_path).unwrap().len();
        assert!(shim_size > SHIM_CLI.len() as u64, "shim too small: {shim_size}");

        // Read back the appended data and verify it's a relative path
        let data = fs::read(shim_path).unwrap();
        let len_bytes: [u8; 4] = data[data.len() - 4..].try_into().unwrap();
        let path_len = u32::from_le_bytes(len_bytes) as usize;
        let path_bytes = &data[data.len() - 4 - path_len..data.len() - 4];
        let rel_path = std::str::from_utf8(path_bytes).unwrap();
        assert!(rel_path.contains("app") && rel_path.contains("tool.exe"), "unexpected relative path: {rel_path}");
        assert!(rel_path.starts_with(".."), "expected relative path with ..: {rel_path}");
    }
}
