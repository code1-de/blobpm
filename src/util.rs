/// Return "" if count is 1, "s" otherwise.
pub(crate) fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

/// Return `singular` if count is 1, `multiple` otherwise.
pub(crate) fn pluralize<'a>(count: usize, singular: &'a str, multiple: &'a str) -> &'a str {
    if count == 1 { singular } else { multiple }
}
