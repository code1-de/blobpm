//! Blob shim — tiny `no_std` launcher that reads a relative target exe path appended
//! to itself, resolves it against its own directory, launches it with the original
//! arguments, waits, and propagates the exit code.
//!
//! Binary format: [PE image][relative target path as UTF-8][u32 LE: path length]
//!
//! The path is relative to the shim's own directory, making the install tree relocatable.

#![no_std]
#![no_main]
#![windows_subsystem = "console"]
#![allow(unsafe_op_in_unsafe_fn)]
// Hand-rolled no_std FFI launcher: these pedantic lints don't fit this context.
// All int casts are between fixed-width types whose values are bounded by the
// surrounding logic (buffers ≤ 32 KiB, path lengths validated before casting);
// the large fixed-size buffers are deliberate (no_std has no heap); and the index
// loops perform explicit bounds-checked copies that read clearer than iterator
// adapters here.
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::large_stack_arrays)]
#![allow(clippy::too_many_lines)]

// --- Win32 FFI ---

type Handle = usize;
const INVALID_HANDLE: Handle = !0;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 1;
const OPEN_EXISTING: u32 = 3;
const FILE_END: u32 = 2;
const INFINITE: u32 = 0xFFFF_FFFF;
const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // (DWORD)-12
const CP_UTF8: u32 = 65001;

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: usize,
    desktop: usize,
    title: usize,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    cb_reserved2: u16,
    reserved2: usize,
    std_input: Handle,
    std_output: Handle,
    std_error: Handle,
}

#[repr(C)]
struct ProcessInformation {
    process: Handle,
    thread: Handle,
    process_id: u32,
    thread_id: u32,
}

unsafe extern "system" {
    fn GetModuleFileNameW(module: usize, buf: *mut u16, size: u32) -> u32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: usize,
        disposition: u32,
        flags: u32,
        template: usize,
    ) -> Handle;
    fn SetFilePointer(file: Handle, distance: i32, distance_high: *mut i32, method: u32) -> u32;
    fn ReadFile(file: Handle, buf: *mut u8, to_read: u32, read: *mut u32, overlapped: usize) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetCommandLineW() -> *const u16;
    fn CreateProcessW(
        app: *const u16,
        cmdline: *mut u16,
        proc_attr: usize,
        thread_attr: usize,
        inherit: i32,
        flags: u32,
        env: usize,
        dir: usize,
        si: *const StartupInfoW,
        pi: *mut ProcessInformation,
    ) -> i32;
    fn WaitForSingleObject(handle: Handle, ms: u32) -> u32;
    fn GetExitCodeProcess(process: Handle, code: *mut u32) -> i32;
    fn ExitProcess(code: u32) -> !;
    fn GetStdHandle(id: u32) -> Handle;
    fn WriteFile(file: Handle, buf: *const u8, to_write: u32, written: *mut u32, overlapped: usize) -> i32;
    fn MultiByteToWideChar(cp: u32, flags: u32, src: *const u8, src_len: i32, dst: *mut u16, dst_len: i32) -> i32;
}

// --- Helpers ---

unsafe fn die(msg: &[u8]) -> ! {
    let h = GetStdHandle(STD_ERROR_HANDLE);
    let mut w = 0u32;
    WriteFile(h, msg.as_ptr(), msg.len() as u32, &raw mut w, 0);
    ExitProcess(127)
}

/// Skip past argv[0] in a Windows command line (handles quoting).
unsafe fn skip_argv0(cmd: *const u16) -> *const u16 {
    let mut p = cmd;
    if *p == b'"' as u16 {
        // Quoted: skip to closing quote
        p = p.add(1);
        while *p != 0 && *p != b'"' as u16 {
            p = p.add(1);
        }
        if *p == b'"' as u16 {
            p = p.add(1);
        }
    } else {
        // Unquoted: skip to first space
        while *p != 0 && *p != b' ' as u16 && *p != b'\t' as u16 {
            p = p.add(1);
        }
    }
    // Skip whitespace between argv[0] and argv[1]
    while *p == b' ' as u16 || *p == b'\t' as u16 {
        p = p.add(1);
    }
    p
}

// --- Entry point ---

#[unsafe(no_mangle)]
unsafe extern "C" fn mainCRTStartup() -> ! {
    // 1. Get own exe path
    let mut exe_path = [0u16; 1024];
    let len = GetModuleFileNameW(0, exe_path.as_mut_ptr(), exe_path.len() as u32);
    if len == 0 {
        die(b"blob-shim: cannot get exe path\r\n");
    }

    // 2. Open own exe file
    let file = CreateFileW(exe_path.as_ptr(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if file == INVALID_HANDLE {
        die(b"blob-shim: cannot open exe\r\n");
    }

    // 3. Read last 4 bytes: path length
    SetFilePointer(file, -4, core::ptr::null_mut(), FILE_END);
    let mut len_buf = [0u8; 4];
    let mut read = 0u32;
    ReadFile(file, len_buf.as_mut_ptr(), 4, &raw mut read, 0);
    let path_len = u32::from_le_bytes(len_buf) as usize;

    if path_len == 0 || path_len > 32768 {
        CloseHandle(file);
        die(b"blob-shim: no target path appended\r\n");
    }

    // 4. Read target path (UTF-8)
    let mut target_utf8 = [0u8; 32768];
    SetFilePointer(file, -(4 + path_len as i32), core::ptr::null_mut(), FILE_END);
    ReadFile(file, target_utf8.as_mut_ptr(), path_len as u32, &raw mut read, 0);
    CloseHandle(file);

    // 5. Convert relative target path UTF-8 → UTF-16
    let mut rel_wide = [0u16; 1024];
    let rel_len = MultiByteToWideChar(
        CP_UTF8,
        0,
        target_utf8.as_ptr(),
        path_len as i32,
        rel_wide.as_mut_ptr(),
        rel_wide.len() as i32,
    );
    if rel_len <= 0 {
        die(b"blob-shim: invalid target path\r\n");
    }

    // 6. Resolve relative path against shim's own directory
    //    Find last backslash in exe_path to get the directory
    let mut full_target = [0u16; 2048];
    let mut dir_end = 0usize;
    for i in 0..len as usize {
        if exe_path[i] == b'\\' as u16 || exe_path[i] == b'/' as u16 {
            dir_end = i + 1;
        }
    }
    // Copy directory prefix, then append the relative target path. Both copies are
    // bounds-checked against full_target, reserving the final slot for the null
    // terminator, so an overlong exe dir + target path can never write past the buffer.
    let mut pos = 0usize;
    for i in 0..dir_end {
        if pos >= full_target.len() - 1 {
            die(b"blob-shim: resolved target path too long\r\n");
        }
        full_target[pos] = exe_path[i];
        pos += 1;
    }
    // Append relative target path
    for i in 0..rel_len as usize {
        if pos >= full_target.len() - 1 {
            die(b"blob-shim: resolved target path too long\r\n");
        }
        // Normalize forward slashes to backslashes
        full_target[pos] = if rel_wide[i] == b'/' as u16 { b'\\' as u16 } else { rel_wide[i] };
        pos += 1;
    }
    full_target[pos] = 0;
    let target_len = pos;

    // 7. Build command line: "full_target" + rest of original args
    let orig_cmd = GetCommandLineW();
    let rest = skip_argv0(orig_cmd);

    let mut cmdline = [0u16; 32768];
    pos = 0;

    // Opening quote
    cmdline[pos] = b'"' as u16;
    pos += 1;
    // Full target path
    for i in 0..target_len {
        if pos >= cmdline.len() - 2 {
            break;
        }
        cmdline[pos] = full_target[i];
        pos += 1;
    }
    // Closing quote
    cmdline[pos] = b'"' as u16;
    pos += 1;

    // Append rest of original args (with space separator if non-empty)
    if *rest != 0 {
        cmdline[pos] = b' ' as u16;
        pos += 1;
        let mut r = rest;
        while *r != 0 && pos < cmdline.len() - 1 {
            cmdline[pos] = *r;
            pos += 1;
            r = r.add(1);
        }
    }
    cmdline[pos] = 0; // null-terminate

    // 8. Launch process
    let mut si: StartupInfoW = core::mem::zeroed();
    si.cb = core::mem::size_of::<StartupInfoW>() as u32;
    let mut pi: ProcessInformation = core::mem::zeroed();

    let ok = CreateProcessW(
        core::ptr::null(),
        cmdline.as_mut_ptr(),
        0,
        0,
        1, // inherit handles
        0,
        0,
        0,
        &raw const si,
        &raw mut pi,
    );
    if ok == 0 {
        die(b"blob-shim: cannot launch target\r\n");
    }

    // 9. Wait and propagate exit code
    WaitForSingleObject(pi.process, INFINITE);
    let mut exit_code = 1u32;
    GetExitCodeProcess(pi.process, &raw mut exit_code);
    CloseHandle(pi.process);
    CloseHandle(pi.thread);

    ExitProcess(exit_code)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(127) }
}
