use std::io::IsTerminal;

/// Return "" if count is 1, "s" otherwise.
pub(crate) fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

/// Return `singular` if count is 1, `multiple` otherwise.
pub(crate) fn pluralize<'a>(count: usize, singular: &'a str, multiple: &'a str) -> &'a str {
    if count == 1 { singular } else { multiple }
}

/// Replace control characters (C0, DEL, C1) with `?` so untrusted server-provided
/// strings (package names, versions, descriptions, file paths) cannot inject terminal
/// escape sequences when printed. Character count is preserved (1:1), so it is safe to
/// use after computing column widths.
pub(crate) fn sanitize_display(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// Wrap a message in ANSI red if stderr is a terminal and `NO_COLOR` is not set.
pub(crate) fn red(msg: &str) -> String {
    if std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none() {
        format!("\x1b[31m{msg}\x1b[0m")
    } else {
        msg.to_string()
    }
}
