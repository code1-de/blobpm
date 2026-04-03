//! Platform-specific functionality (file permissions, path conventions, etc.)

use std::io;
use std::path::Path;

/// Normalize a path string to manifest convention (always forward slashes).
/// Backslash-as-filename-char is not a supported use case, so we convert on all platforms.
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

/// Rename a file by appending `.<N>.__blob__` where N is the first free number.
#[cfg(windows)]
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
    use windows::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
    use windows::core::PCWSTR;

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    unsafe { MoveFileExW(PCWSTR(wide.as_ptr()), None, MOVEFILE_DELAY_UNTIL_REBOOT) }.is_ok()
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
pub(crate) fn normalize_for_compare(p: &Path) -> String {
    p.to_string_lossy().to_lowercase()
}

#[cfg(not(windows))]
pub(crate) fn normalize_for_compare(p: &Path) -> String {
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

/// Recursively delete all `*.__blob__` files under the given directories. Returns count of deleted files.
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
            if name_str.ends_with(BLOB_RENAME_MARKER) && std::fs::remove_file(&path).is_ok() {
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
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_EXECUTE, FILE_FLAG_DELETE_ON_CLOSE, FILE_SHARE_DELETE, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    };
    use windows::core::{PCWSTR, PWSTR};

    let tmp_dir = std::env::temp_dir();
    let pid = std::process::id();
    let tmp_path = tmp_dir.join(format!("blob_cleanup_{pid}.exe"));

    // Read the OLD (renamed) exe — it's the currently running process image.
    let exe_data = std::fs::read(old_exe)?;

    // Write temp exe, then re-open with DELETE_ON_CLOSE for auto-cleanup
    std::fs::write(&tmp_path, &exe_data)?;

    // Re-open with FILE_EXECUTE + DELETE_ON_CLOSE — file auto-deletes when all handles close.
    // Handle intentionally leaked — closes when this process exits, triggering deletion
    // after the spawned cleanup process has also exited.
    let wide_path: Vec<u16> = tmp_path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let _delete_handle = unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            FILE_EXECUTE.0,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_DELETE_ON_CLOSE,
            None,
        )
    };

    // Spawn: blob_cleanup.exe cleanup --self-update <dir>
    let tmp_path_str = tmp_path.to_string_lossy();
    let dir_str = blob_dir.to_string_lossy();
    let mut cmdline: Vec<u16> = format!("\"{tmp_path_str}\" cleanup --self-update \"{dir_str}\"")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Flush before spawning the cleanup process so output doesn't interleave
    let _ = io::Write::flush(&mut io::stdout());
    let _ = io::Write::flush(&mut io::stderr());

    let mut si = STARTUPINFOW::default();
    #[allow(clippy::cast_possible_truncation)] // STARTUPINFOW size always fits in u32
    {
        si.cb = std::mem::size_of_val(&si) as u32;
    }
    let mut pi = PROCESS_INFORMATION::default();

    unsafe {
        CreateProcessW(
            None,
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS::default(),
            None,
            None,
            &raw const si,
            &raw mut pi,
        )
    }
    .map_err(|e| io::Error::other(format!("[self-update] CreateProcessW: {e}")))?;

    unsafe {
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Path convention tests ---

    #[test]
    fn manifest_path_converts_backslashes() {
        assert_eq!(to_manifest_path("util/sub"), "util/sub");
        assert_eq!(to_manifest_path("util\\sub"), "util/sub");
        assert_eq!(to_manifest_path("a\\b\\c"), "a/b/c");
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
