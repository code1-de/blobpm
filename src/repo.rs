use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub description: String,
    pub files: BTreeMap<String, String>,
    pub dependencies: Vec<String>,
    /// Shim links: dest path → target path (both relative to `base_dir`/`path_map`).
    /// E.g. `{"bin/git.exe": "git/mingw64/bin/git.exe"}` creates a shim launcher.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub latest: String,
    pub description: String,
}

// --- Version parsing and comparison (used by both client and server) ---

/// A parsed version: numeric dot-separated segments plus a qualifier for the whole version.
/// Trailing zeros are ignored: 1.0 == 1.0.0.
/// The qualifier (letter suffix or pre-release tag) applies to the entire version, not per segment.
///
/// Examples:
/// - "1.10"       -> segments [1, 10], Plain
/// - "1.10a"      -> segments [1, 10], LetterSuffix("a")
/// - "1.10-beta2" -> segments [1, 10], PreRelease("beta", 2)
#[derive(Debug, Eq, PartialEq)]
struct ParsedVersion {
    segments: Vec<u64>,
    qualifier: VersionQualifier,
}

#[derive(Debug, Eq, PartialEq)]
enum VersionQualifier {
    PreRelease { tag: String, num: u64 },
    Plain,
    LetterSuffix(String),
}

impl ParsedVersion {
    fn parse(s: &str) -> Self {
        // Split on '-' to detect pre-release (e.g. "1.10-beta2")
        let (main, prerelease) = if let Some((m, p)) = s.split_once('-') { (m, Some(p)) } else { (s, None) };

        let parts: Vec<&str> = main.split('.').collect();

        if let Some(pre) = prerelease {
            let segments = parts.iter().map(|p| p.parse().unwrap_or(0)).collect();
            // Split tag into text + trailing number: "beta12" -> ("beta", 12)
            let num_start = pre.find(|c: char| c.is_ascii_digit()).unwrap_or(pre.len());
            let tag = pre[..num_start].to_lowercase();
            let num = pre[num_start..].parse().unwrap_or(0);
            Self { segments, qualifier: VersionQualifier::PreRelease { tag, num } }
        } else {
            // Check last part for trailing letter suffix (e.g. "1a" in "1.0.1a")
            let last = parts.last().copied().unwrap_or("");
            let num_end = last.find(|c: char| !c.is_ascii_digit()).unwrap_or(last.len());
            let suffix = &last[num_end..];

            let mut segments: Vec<u64> = parts[..parts.len() - 1].iter().map(|p| p.parse().unwrap_or(0)).collect();
            segments.push(last[..num_end].parse().unwrap_or(0));

            if suffix.is_empty() {
                Self { segments, qualifier: VersionQualifier::Plain }
            } else {
                Self { segments, qualifier: VersionQualifier::LetterSuffix(suffix.to_lowercase()) }
            }
        }
    }

    /// Render back to a canonical version string.
    /// Strips trailing zero segments, lowercases suffixes/tags.
    fn to_canonical(&self) -> String {
        use VersionQualifier::{LetterSuffix, Plain, PreRelease};

        // Strip trailing zeros
        let mut segs = self.segments.clone();
        while segs.len() > 1 && segs.last() == Some(&0) {
            segs.pop();
        }

        let base: String = segs.iter().map(u64::to_string).collect::<Vec<_>>().join(".");
        match &self.qualifier {
            Plain => base,
            LetterSuffix(s) => format!("{base}{s}"),
            PreRelease { tag, num } => {
                if *num == 0 {
                    format!("{base}-{tag}")
                } else {
                    format!("{base}-{tag}{num}")
                }
            }
        }
    }
}

impl Ord for ParsedVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use VersionQualifier::{LetterSuffix, Plain, PreRelease};

        // Compare numeric segments, treating missing trailing segments as 0
        let max_len = self.segments.len().max(other.segments.len());
        for i in 0..max_len {
            let a = self.segments.get(i).copied().unwrap_or(0);
            let b = other.segments.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                std::cmp::Ordering::Equal => {}
                ord => return ord,
            }
        }
        // Segments equal — compare qualifier: PreRelease < Plain < LetterSuffix
        match (&self.qualifier, &other.qualifier) {
            (Plain, Plain) => std::cmp::Ordering::Equal,
            (PreRelease { tag: t1, num: n1 }, PreRelease { tag: t2, num: n2 }) => t1.cmp(t2).then(n1.cmp(n2)),
            (LetterSuffix(a), LetterSuffix(b)) => a.cmp(b),
            (PreRelease { .. }, Plain | LetterSuffix(_)) | (Plain, LetterSuffix(_)) => std::cmp::Ordering::Less,
            (Plain | LetterSuffix(_), PreRelease { .. }) | (LetterSuffix(_), Plain) => std::cmp::Ordering::Greater,
        }
    }
}

impl PartialOrd for ParsedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Compare two version strings.
///
/// Rules:
/// - Dot-separated numeric segments, compared numerically (1.9 < 1.10)
/// - Trailing zeros ignored (1.0 == 1.0.0)
/// - Pre-release (1.10-beta) < plain (1.10) < letter suffix (1.10a)
/// - Pre-release tags: name lexicographic, then number numeric (alpha < beta2 < beta12 < rc1)
/// - Letter suffixes: lexicographic (1.10a < 1.10b)
/// - Case insensitive: -BETA == -beta, 1.0A == 1.0a
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    ParsedVersion::parse(a).cmp(&ParsedVersion::parse(b))
}

/// Canonicalize a version string: strip trailing `.0` segments, lowercase suffixes/tags.
/// Examples: "1.0.0" -> "1", "2.0-BETA" -> "2-beta", "1.10A" -> "1.10a"
pub fn canonicalize_version(v: &str) -> String {
    ParsedVersion::parse(v).to_canonical()
}

// --- Server-only: repo scanning ---

#[cfg(feature = "server")]
pub use server_only::*;

#[cfg(feature = "server")]
mod server_only {
    use super::{BTreeMap, IndexEntry, Manifest, version_cmp};
    use std::path::Path;
    use std::{fs, io};

    #[derive(Debug, Clone)]
    pub struct PackageInfo {
        pub latest: String,
        pub description: String,
        pub versions: Vec<String>,
    }

    #[derive(Debug)]
    pub struct RepoIndex {
        pub packages: BTreeMap<String, PackageInfo>,
    }

    impl RepoIndex {
        /// Scan a repository directory and build the index.
        ///
        /// # Errors
        /// Returns an error if the repo path or its contents cannot be read.
        pub fn scan(repo_path: &Path) -> io::Result<Self> {
            let packages_dir = repo_path.join("packages");
            let mut packages = BTreeMap::new();

            if !packages_dir.is_dir() {
                return Ok(Self { packages });
            }

            for entry in fs::read_dir(&packages_dir)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }

                let pkg_name = entry.file_name().to_string_lossy().to_string();
                let mut versions = Vec::new();

                for ver_entry in fs::read_dir(entry.path())? {
                    let ver_entry = ver_entry?;
                    if !ver_entry.file_type()?.is_dir() {
                        continue;
                    }
                    let ver = ver_entry.file_name().to_string_lossy().to_string();
                    let manifest_path = ver_entry.path().join("manifest.json");
                    if manifest_path.is_file() {
                        versions.push(ver);
                    }
                }

                if versions.is_empty() {
                    continue;
                }

                versions.sort_by(|a, b| version_cmp(a, b));

                let Some(latest) = versions.last().cloned() else {
                    continue;
                };
                let description = fs::read(entry.path().join(&latest).join("manifest.json"))
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Manifest>(&b).ok())
                    .map(|m| m.description)
                    .unwrap_or_default();
                packages.insert(pkg_name, PackageInfo { latest, description, versions });
            }

            Ok(Self { packages })
        }

        /// Build a summary index mapping package names to their latest version and description.
        #[must_use]
        pub fn index_summary(&self) -> BTreeMap<String, IndexEntry> {
            self.packages
                .iter()
                .map(|(name, info)| {
                    (name.clone(), IndexEntry { latest: info.latest.clone(), description: info.description.clone() })
                })
                .collect()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::Path;

        fn create_test_repo(base: &Path) {
            let pkg_dir = base.join("packages").join("testpkg").join("1.0");
            fs::create_dir_all(&pkg_dir).unwrap();
            fs::write(
                pkg_dir.join("manifest.json"),
                r#"{"name":"testpkg","description":"A test package","files":{"test.exe":"util/"},"dependencies":[]}"#,
            )
            .unwrap();

            let pkg_dir2 = base.join("packages").join("testpkg").join("2.0");
            fs::create_dir_all(&pkg_dir2).unwrap();
            fs::write(
                pkg_dir2.join("manifest.json"),
                r#"{"name":"testpkg","description":"A test package v2","files":{"test.exe":"util/"},"dependencies":[]}"#,
            )
            .unwrap();

            let other_dir = base.join("packages").join("other").join("0.1");
            fs::create_dir_all(&other_dir).unwrap();
            fs::write(
                other_dir.join("manifest.json"),
                r#"{"name":"other","description":"Another package","files":{"other.exe":"bin/"},"dependencies":["testpkg"]}"#,
            )
            .unwrap();
        }

        #[test]
        fn scan_finds_packages() {
            let tmp = tempfile::tempdir().unwrap();
            create_test_repo(tmp.path());

            let index = RepoIndex::scan(tmp.path()).unwrap();
            assert_eq!(index.packages.len(), 2);
            assert!(index.packages.contains_key("testpkg"));
            assert!(index.packages.contains_key("other"));
        }

        #[test]
        fn scan_finds_latest_version() {
            let tmp = tempfile::tempdir().unwrap();
            create_test_repo(tmp.path());

            let index = RepoIndex::scan(tmp.path()).unwrap();
            assert_eq!(index.packages["testpkg"].latest, "2.0");
            assert_eq!(index.packages["testpkg"].versions, vec!["1.0", "2.0"]);
        }

        #[test]
        fn scan_empty_repo() {
            let tmp = tempfile::tempdir().unwrap();
            let index = RepoIndex::scan(tmp.path()).unwrap();
            assert!(index.packages.is_empty());
        }

        #[test]
        fn index_summary() {
            let tmp = tempfile::tempdir().unwrap();
            create_test_repo(tmp.path());

            let index = RepoIndex::scan(tmp.path()).unwrap();
            let summary = index.index_summary();
            assert_eq!(summary["testpkg"].latest, "2.0");
            assert_eq!(summary["other"].latest, "0.1");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering_basic() {
        assert_eq!(version_cmp("1.0", "2.0"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.9", "1.10"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("2.0", "2.0"), std::cmp::Ordering::Equal);
        assert_eq!(version_cmp("1.0", "1.0.1"), std::cmp::Ordering::Less);
        // Trailing zeros are irrelevant
        assert_eq!(version_cmp("1.0", "1.0.0"), std::cmp::Ordering::Equal);
        assert_eq!(version_cmp("1", "1.0.0.0"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn version_ordering_suffixes() {
        // Letter suffix > no suffix (1.10 < 1.10a, like OpenSSL)
        assert_eq!(version_cmp("1.10", "1.10a"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.10a", "1.10b"), std::cmp::Ordering::Less);
        // Letter suffix < next dot-release
        assert_eq!(version_cmp("1.10a", "1.10.1"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.0.1a", "1.0.1b"), std::cmp::Ordering::Less);
    }

    #[test]
    fn version_ordering_prerelease() {
        // Pre-release < no suffix
        assert_eq!(version_cmp("1.10-beta", "1.10"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.10", "1.10-beta"), std::cmp::Ordering::Greater);
        // Pre-release tags ordered lexicographically
        assert_eq!(version_cmp("1.10-alpha", "1.10-beta"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.10-beta", "1.10-rc"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.10-alpha", "1.10-rc"), std::cmp::Ordering::Less);
        // Letter suffix > pre-release
        assert_eq!(version_cmp("1.10a", "1.10-beta"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn version_ordering_prerelease_numbers() {
        // Numeric suffixes on pre-release tags compared numerically
        assert_eq!(version_cmp("1.10-beta", "1.10-beta2"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.10-beta2", "1.10-beta12"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.10-rc1", "1.10-rc2"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.10-alpha3", "1.10-beta"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.10-rc12", "1.10"), std::cmp::Ordering::Less);
    }

    #[test]
    fn version_ordering_case_insensitive() {
        assert_eq!(version_cmp("1.0-BETA", "1.0-beta"), std::cmp::Ordering::Equal);
        assert_eq!(version_cmp("1.0A", "1.0a"), std::cmp::Ordering::Equal);
        assert_eq!(version_cmp("1.0-RC1", "1.0-rc1"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn version_ordering_mixed() {
        // 1.9 < 1.10-beta < 1.10-beta2 < 1.10-beta12 < 1.10 < 1.10a < 1.10b < 1.10.1
        let mut versions = vec!["1.10b", "1.10-beta", "1.9", "1.10.1", "1.10", "1.10a", "1.10-beta2", "1.10-beta12"];
        versions.sort_by(|a, b| version_cmp(a, b));
        assert_eq!(versions, vec!["1.9", "1.10-beta", "1.10-beta2", "1.10-beta12", "1.10", "1.10a", "1.10b", "1.10.1"]);
    }

    #[test]
    fn canonicalize_strips_trailing_zeros() {
        assert_eq!(canonicalize_version("1.0.0"), "1");
        assert_eq!(canonicalize_version("1.0"), "1");
        assert_eq!(canonicalize_version("2.1.0"), "2.1");
        assert_eq!(canonicalize_version("1.0.1"), "1.0.1");
        assert_eq!(canonicalize_version("0"), "0");
    }

    #[test]
    fn canonicalize_lowercases() {
        assert_eq!(canonicalize_version("1.0-BETA"), "1-beta");
        assert_eq!(canonicalize_version("2.0-RC1"), "2-rc1");
        assert_eq!(canonicalize_version("1.10A"), "1.10a");
        assert_eq!(canonicalize_version("1.0.0-Beta2"), "1-beta2");
    }

    #[test]
    fn canonicalize_qualifier_with_trailing_zeros() {
        assert_eq!(canonicalize_version("1.0.0a"), "1a");
        assert_eq!(canonicalize_version("2.0.0-beta3"), "2-beta3");
        assert_eq!(canonicalize_version("1.0.0-rc"), "1-rc");
        assert_eq!(canonicalize_version("3.0b"), "3b");
    }

    #[test]
    fn canonical_and_non_canonical_compare_equal() {
        assert_eq!(version_cmp("1.0.0", "1"), std::cmp::Ordering::Equal);
        assert_eq!(version_cmp("1.0.0a", "1a"), std::cmp::Ordering::Equal);
        assert_eq!(version_cmp("1.0.0-beta", "1-beta"), std::cmp::Ordering::Equal);
        assert_eq!(version_cmp("2.0.0-RC1", "2-rc1"), std::cmp::Ordering::Equal);
        assert_eq!(version_cmp("1.0.0-Beta2", "1-BETA2"), std::cmp::Ordering::Equal);
    }
}
