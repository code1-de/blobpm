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
        EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
        SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_TYPE, TRUSTEE_W,
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
                MultipleTrusteeOperation:
                    windows::Win32::Security::Authorization::MULTIPLE_TRUSTEE_OPERATION(0),
            },
        };

        let mut new_acl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
        SetEntriesInAclW(Some(&[ea]), None, &raw mut new_acl)
            .ok()
            .map_err(|e| {
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
}
