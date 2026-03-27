use std::io::IsTerminal;

/// Return "" if count is 1, "s" otherwise.
pub(crate) fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

/// Return `singular` if count is 1, `multiple` otherwise.
pub(crate) fn pluralize<'a>(count: usize, singular: &'a str, multiple: &'a str) -> &'a str {
    if count == 1 { singular } else { multiple }
}

/// Wrap a message in ANSI red if stderr is a terminal and `NO_COLOR` is not set.
pub(crate) fn red(msg: &str) -> String {
    if std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none() {
        format!("\x1b[31m{msg}\x1b[0m")
    } else {
        msg.to_string()
    }
}
