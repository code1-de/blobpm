//! Platform-specific functionality (file permissions, path conventions, etc.)

use std::io;
use std::path::Path;

/// Normalize a path string to manifest convention (always forward slashes).
/// On Windows, converts `\` to `/`. On Linux, `\` is a valid filename character — left as-is.
#[cfg(windows)]
pub(crate) fn to_manifest_path(path: &str) -> String {
    path.replace('\\', "/")
}

/// On Linux, also convert backslashes — manifests always use forward slashes,
/// and backslash-as-filename-char is not a supported use case.
#[cfg(not(windows))]
pub(crate) fn to_manifest_path(path: &str) -> String {
    path.replace('\\', "/")
}

/// Convert a manifest path (forward slashes) to the native OS separator.
#[cfg(windows)]
pub(crate) fn to_native_path(path: &str) -> String {
    path.replace('/', "\\")
}

/// Convert a manifest path (forward slashes) to the native OS separator.
/// On Unix, manifest convention already matches — no conversion needed.
#[cfg(not(windows))]
pub(crate) fn to_native_path(path: &str) -> String {
    path.to_string()
}

/// Restrict file permissions to owner-only, but only if the file still has default
/// (inherited) permissions. If the user has customized the ACLs, don't touch them.
/// Returns `Ok(true)` if permissions were changed, `Ok(false)` if already customized.
#[cfg(windows)]
pub fn restrict_to_owner_if_inherited(path: &Path) -> io::Result<bool> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetNamedSecurityInfoW,
        TRUSTEE_IS_SID, TRUSTEE_TYPE, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, OBJECT_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };

    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
    const SE_DACL_PROTECTED: u16 = 0x1000;
    const PROTECTED_DACL: OBJECT_SECURITY_INFORMATION = OBJECT_SECURITY_INFORMATION(0x8000_0000);

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let pcwstr = windows::core::PCWSTR(wide.as_ptr());

    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let mut owner = PSID::default();
        let mut dacl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();

        GetNamedSecurityInfoW(
            pcwstr,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            Some(&raw mut dacl),
            None,
            &raw mut sd,
        )
        .ok()
        .map_err(|e| io::Error::other(format!("GetNamedSecurityInfo: {e}")))?;

        // Check if DACL is already protected (user has customized permissions)
        let mut control: u16 = 0;
        let mut revision = 0u32;
        GetSecurityDescriptorControl(sd, &raw mut control, &raw mut revision)
            .map_err(|e| io::Error::other(format!("GetSecurityDescriptorControl: {e}")))?;

        if control & SE_DACL_PROTECTED != 0 {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            return Ok(false);
        }

        // Build new ACL: only owner gets full control
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: SET_ACCESS,
            grfInheritance: windows::Win32::Security::ACE_FLAGS(0), // NO_INHERITANCE
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_TYPE(0),
                ptstrName: windows::core::PWSTR(owner.0.cast::<u16>()),
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: windows::Win32::Security::Authorization::MULTIPLE_TRUSTEE_OPERATION(0),
            },
        };

        let mut new_acl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
        SetEntriesInAclW(Some(&[ea]), None, &raw mut new_acl).ok().map_err(|e| {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            io::Error::other(format!("SetEntriesInAcl: {e}"))
        })?;

        // Set new DACL with PROTECTED flag (stops inheritance)
        let result = SetNamedSecurityInfoW(
            pcwstr,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL,
            None,
            None,
            Some(new_acl),
            None,
        )
        .ok();

        let _ = LocalFree(Some(HLOCAL(new_acl.cast())));
        let _ = LocalFree(Some(HLOCAL(sd.0)));

        result.map_err(|e| io::Error::other(format!("SetNamedSecurityInfo: {e}")))?;
    }

    Ok(true)
}

/// On Linux: set file permissions to 0600 (owner read/write only).
/// Returns `Ok(true)` if permissions were changed, `Ok(false)` if already restrictive.
#[cfg(not(windows))]
pub fn restrict_to_owner_if_inherited(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode <= 0o600 {
        return Ok(false);
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(true)
}

/// Blob cleanup marker for renamed-in-use files.
pub(crate) const BLOB_RENAME_MARKER: &str = ".__blob__";

/// Tracks the path of a self-renamed exe (set during install if the running blob.exe was renamed).
static SELF_RENAMED_EXE: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// Try to create/overwrite a file. If it fails with access denied (file in use),
/// rename the old file to `name.__blob_N` and retry. Returns `Some(renamed_path)` if a rename was needed.
#[cfg(windows)]
pub(crate) fn write_or_rename(dest: &Path, data: &[u8]) -> io::Result<Option<std::path::PathBuf>> {
    match std::fs::write(dest, data) {
        Ok(()) => Ok(None),
        Err(e) if matches!(e.raw_os_error(), Some(5 | 32)) || e.kind() == io::ErrorKind::PermissionDenied => {
            // Error 5 = ACCESS_DENIED, 32 = SHARING_VIOLATION — file likely in use. Rename and retry.
            let renamed = rename_with_blob_suffix(dest)?;
            std::fs::write(dest, data)?;
            // Try to schedule deletion on reboot (requires admin, may fail silently)
            let _ = move_file_on_reboot(&renamed);
            // Track self-rename if this is our own exe
            if let Ok(own_exe) = std::env::current_exe()
                && dunce::canonicalize(dest).ok() == dunce::canonicalize(&own_exe).ok()
                && let Ok(mut guard) = SELF_RENAMED_EXE.lock()
            {
                *guard = Some(renamed.clone());
            }
            Ok(Some(renamed))
        }
        Err(e) => Err(e),
    }
}

#[cfg(not(windows))]
pub(crate) fn write_or_rename(dest: &Path, data: &[u8]) -> io::Result<Option<std::path::PathBuf>> {
    std::fs::write(dest, data)?;
    Ok(None)
}

/// Rename a file by appending `.__blob_N` where N is the first free number.
fn rename_with_blob_suffix(path: &Path) -> io::Result<std::path::PathBuf> {
    let name = path.to_string_lossy();
    for i in 0u32..1000 {
        let renamed = std::path::PathBuf::from(format!("{name}.{i}{BLOB_RENAME_MARKER}"));
        if !renamed.exists() {
            std::fs::rename(path, &renamed).map_err(|e| {
                io::Error::new(e.kind(), format!("rename {} -> {}: {e}", path.display(), renamed.display()))
            })?;
            return Ok(renamed);
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("Too many blob renames for {name}")))
}

/// Schedule a file for deletion on reboot via `MoveFileExW`. Requires admin; returns Ok(false) if it fails.
#[cfg(windows)]
fn move_file_on_reboot(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_DELAY_UNTIL_REBOOT: u32 = 4;

    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let ok = unsafe { MoveFileExW(wide.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
    ok != 0
}

/// Returns the path of the self-renamed exe, if any.
pub(crate) fn take_self_renamed_exe() -> Option<std::path::PathBuf> {
    SELF_RENAMED_EXE.lock().ok()?.take()
}

/// Reduce a set of directories to the minimal roots (remove any dir that's a child of another).
/// Lexicographic sort ensures parents come before children, so a single-pass check
/// against the last accepted root suffices. O(n log n) total.
fn minimal_roots(dirs: &std::collections::HashSet<std::path::PathBuf>) -> Vec<std::path::PathBuf> {
    let mut sorted: Vec<std::path::PathBuf> = dirs.iter().filter_map(|d| dunce::canonicalize(d).ok()).collect();
    sorted.sort_by_key(|a| normalize_for_compare(a));
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    for dir in sorted {
        if roots.last().is_some_and(|root| path_starts_with(&dir, root)) {
            continue;
        }
        roots.push(dir);
    }
    roots
}

/// Case-insensitive path comparison on Windows, case-sensitive elsewhere.
#[cfg(windows)]
fn normalize_for_compare(p: &Path) -> String {
    p.to_string_lossy().to_lowercase()
}

#[cfg(not(windows))]
fn normalize_for_compare(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Case-insensitive `starts_with` on Windows, case-sensitive elsewhere.
#[cfg(windows)]
fn path_starts_with(child: &Path, parent: &Path) -> bool {
    let c = child.to_string_lossy().to_lowercase();
    let p = parent.to_string_lossy().to_lowercase();
    c.starts_with(&p) && (c.len() == p.len() || c.as_bytes().get(p.len()) == Some(&b'\\'))
}

#[cfg(not(windows))]
fn path_starts_with(child: &Path, parent: &Path) -> bool {
    child.starts_with(parent)
}

/// Recursively delete all `*.__blob_*` files under the given directories. Returns count of deleted files.
pub(crate) fn cleanup_blob_renames(dirs: &std::collections::HashSet<std::path::PathBuf>) -> u32 {
    let roots = minimal_roots(dirs);
    let mut count = 0u32;
    for root in &roots {
        cleanup_recurse(root, &mut count);
    }
    count
}

fn cleanup_recurse(dir: &Path, count: &mut u32) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            cleanup_recurse(&path, count);
        } else {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.contains(BLOB_RENAME_MARKER) && std::fs::remove_file(&path).is_ok() {
                println!("  Deleted {}", path.display());
                *count += 1;
            }
        }
    }
}

/// Run cleanup with retry loop for self-update scenario.
/// Waits with exponential backoff: 0.1s, 0.2s, 0.4s, 0.8s, 1.0s, 1.0s, ... until ~5s total.
pub(crate) fn cleanup_with_retry(dir: &Path) -> u32 {
    let mut dirs = std::collections::HashSet::new();
    dirs.insert(dir.to_path_buf());
    let mut total_wait = 0.0f64;
    let mut delay = 0.1f64;
    loop {
        let count = cleanup_blob_renames(&dirs);
        if count > 0 || total_wait >= 5.0 {
            return count;
        }
        std::thread::sleep(std::time::Duration::from_secs_f64(delay));
        total_wait += delay;
        delay = (delay * 2.0).min(1.0);
    }
}

/// Copy the current exe to a temp file opened with `DELETE_ON_CLOSE`, then spawn it
/// with the given arguments. The temp file is opened with `DELETE_ON_CLOSE` so it
/// auto-deletes when the cleanup process exits.
#[cfg(windows)]
pub(crate) fn spawn_self_cleanup(blob_dir: &Path, old_exe: &Path) -> io::Result<()> {
    unsafe extern "system" {
        fn GetTempPathW(len: u32, buf: *mut u16) -> u32;
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: usize,
            disp: u32,
            flags: u32,
            template: usize,
        ) -> isize;
        fn CloseHandle(handle: isize) -> i32;
        fn CreateProcessW(
            app: *const u16,
            cmd: *mut u16,
            pa: usize,
            ta: usize,
            inherit: i32,
            flags: u32,
            env: usize,
            dir: usize,
            si: *const u8,
            pi: *mut u8,
        ) -> i32;
    }

    const FILE_EXECUTE: u32 = 0x20;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_DELETE: u32 = 4;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;

    // Get temp dir
    let mut tmp_buf = [0u16; 512];
    #[allow(clippy::cast_possible_truncation)] // buffer is 512, fits in u32
    let tmp_len = unsafe { GetTempPathW(tmp_buf.len() as u32, tmp_buf.as_mut_ptr()) } as usize;
    let tmp_dir = String::from_utf16_lossy(&tmp_buf[..tmp_len]);
    let pid = std::process::id();
    let tmp_path = format!("{tmp_dir}blob_cleanup_{pid}.exe");

    // Read the OLD (renamed) exe — it's the currently running process image.
    let exe_data = std::fs::read(old_exe)?;

    // Write temp exe, then re-open with DELETE_ON_CLOSE for auto-cleanup
    std::fs::write(&tmp_path, &exe_data)?;

    // Re-open with FILE_EXECUTE + DELETE_ON_CLOSE — file auto-deletes when all handles close.
    // Handle intentionally leaked — closes when this process exits, triggering deletion
    // after the spawned cleanup process has also exited.
    let wide_path: Vec<u16> = tmp_path.encode_utf16().chain(std::iter::once(0)).collect();
    let _delete_handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_EXECUTE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            0,
            OPEN_EXISTING,
            FILE_FLAG_DELETE_ON_CLOSE,
            0,
        )
    };

    // Spawn: blob_cleanup.exe cleanup --self-update <dir>
    let dir_str = blob_dir.to_string_lossy();
    let mut cmdline: Vec<u16> = format!("\"{tmp_path}\" cleanup --self-update \"{dir_str}\"")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut si = [0u8; 104]; // STARTUPINFOW is 104 bytes on 64-bit
    si[0..4].copy_from_slice(&104u32.to_le_bytes()); // cb = sizeof(STARTUPINFOW)
    let mut pi = [0u8; 24]; // PROCESS_INFORMATION

    let ok = unsafe {
        CreateProcessW(std::ptr::null(), cmdline.as_mut_ptr(), 0, 0, 0, 0, 0, 0, si.as_ptr(), pi.as_mut_ptr())
    };

    if ok == 0 {
        let err = io::Error::last_os_error();
        return Err(io::Error::new(err.kind(), format!("[self-update] CreateProcessW: {err}")));
    }

    // Close the process/thread handles from PROCESS_INFORMATION
    let proc_handle = isize::from_le_bytes(pi[0..8].try_into().unwrap());
    let thread_handle = isize::from_le_bytes(pi[8..16].try_into().unwrap());
    unsafe {
        CloseHandle(proc_handle);
        CloseHandle(thread_handle);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Path convention tests ---

    #[test]
    fn manifest_paths_use_forward_slashes() {
        assert_eq!(to_manifest_path("util/sub"), "util/sub");
        assert_eq!(to_manifest_path("already/fine"), "already/fine");
    }

    #[test]
    #[cfg(windows)]
    fn manifest_path_converts_backslash_on_windows() {
        assert_eq!(to_manifest_path("util\\sub"), "util/sub");
        assert_eq!(to_manifest_path("a\\b\\c"), "a/b/c");
    }

    #[test]
    #[cfg(not(windows))]
    fn manifest_path_converts_backslash_on_linux() {
        // Manifests always use forward slashes, even on Linux
        assert_eq!(to_manifest_path("util\\sub"), "util/sub");
    }

    #[test]
    fn manifest_path_preserves_no_separators() {
        assert_eq!(to_manifest_path("file.exe"), "file.exe");
        assert_eq!(to_manifest_path(""), "");
    }

    #[test]
    fn native_path_on_current_os() {
        // Manifest uses /, native should convert to OS separator
        let native = to_native_path("util/sub/dir");
        #[cfg(windows)]
        assert_eq!(native, "util\\sub\\dir");
        #[cfg(not(windows))]
        assert_eq!(native, "util/sub/dir");
    }

    #[test]
    fn native_path_no_separators_unchanged() {
        assert_eq!(to_native_path("file.exe"), "file.exe");
        assert_eq!(to_native_path(""), "");
    }

    #[test]
    fn roundtrip_manifest_to_native_to_manifest() {
        let original = "lib/sub/file.dll";
        let native = to_native_path(original);
        let back = to_manifest_path(&native);
        assert_eq!(back, original, "roundtrip must preserve manifest path");
    }

    // --- Minimal roots tests ---

    #[test]
    fn minimal_roots_removes_children() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let ab = tmp.path().join("a").join("b");
        let c = tmp.path().join("c");
        std::fs::create_dir_all(&ab).unwrap();
        std::fs::create_dir_all(&c).unwrap();

        let mut dirs = std::collections::HashSet::new();
        dirs.insert(a.clone());
        dirs.insert(ab);
        dirs.insert(c.clone());

        let roots = minimal_roots(&dirs);
        assert_eq!(roots.len(), 2);
        assert!(roots.contains(&dunce::canonicalize(&a).unwrap()));
        assert!(roots.contains(&dunce::canonicalize(&c).unwrap()));
    }

    #[test]
    fn minimal_roots_keeps_siblings() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();

        let mut dirs = std::collections::HashSet::new();
        dirs.insert(a.clone());
        dirs.insert(b.clone());

        let roots = minimal_roots(&dirs);
        assert_eq!(roots.len(), 2);
    }

    #[test]
    #[cfg(windows)]
    fn minimal_roots_case_insensitive_on_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("MyDir");
        std::fs::create_dir_all(&dir).unwrap();

        let mut dirs = std::collections::HashSet::new();
        // Same dir, different case — should deduplicate
        dirs.insert(tmp.path().join("MyDir"));
        dirs.insert(tmp.path().join("mydir"));

        let roots = minimal_roots(&dirs);
        // canonicalize resolves both to the same path on Windows
        assert_eq!(roots.len(), 1);
    }

    // --- Recursive cleanup tests ---

    #[test]
    fn cleanup_recursive_finds_nested_blob_files() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub").join("deep");
        std::fs::create_dir_all(&sub).unwrap();

        // Create blob rename files at various depths
        std::fs::write(tmp.path().join("tool.exe.0.__blob__"), b"old").unwrap();
        std::fs::write(sub.join("lib.dll.1.__blob__"), b"old").unwrap();
        // Normal file should not be deleted
        std::fs::write(sub.join("keep.txt"), b"keep").unwrap();

        let mut dirs = std::collections::HashSet::new();
        dirs.insert(tmp.path().to_path_buf());

        let count = cleanup_blob_renames(&dirs);
        assert_eq!(count, 2);
        assert!(!tmp.path().join("tool.exe.0.__blob__").exists());
        assert!(!sub.join("lib.dll.1.__blob__").exists());
        assert!(sub.join("keep.txt").exists());
    }
}
