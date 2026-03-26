use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::{fs, io};

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

/// A parsed version segment: numeric prefix, optional text suffix, optional pre-release tag.
/// Examples: "10" -> (10, "", false), "10a" -> (10, "a", false), "10-beta" -> (10, "beta", true)
#[derive(Debug, Eq, PartialEq)]
struct VersionSegment {
    num: u64,
    suffix: String,
    is_prerelease: bool,
}

impl VersionSegment {
    fn parse(s: &str) -> Self {
        // Split on '-' first to detect pre-release
        let (main, prerelease) = if let Some((m, p)) = s.split_once('-') { (m, Some(p)) } else { (s, None) };

        // Extract leading digits and trailing text from main part
        let num_end = main.find(|c: char| !c.is_ascii_digit()).unwrap_or(main.len());
        let num = main[..num_end].parse().unwrap_or(0);
        let suffix = if let Some(pre) = prerelease { pre.to_string() } else { main[num_end..].to_string() };

        Self { num, suffix, is_prerelease: prerelease.is_some() }
    }
}

impl Ord for VersionSegment {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare numeric part first
        self.num.cmp(&other.num).then_with(|| {
            // No suffix > any suffix (1.10 > 1.10a > 1.10-beta)
            // Pre-release < letter suffix (1.10-beta < 1.10a)
            match (self.suffix.is_empty(), other.suffix.is_empty()) {
                (true, true) => std::cmp::Ordering::Equal,
                (true, false) => std::cmp::Ordering::Greater,
                (false, true) => std::cmp::Ordering::Less,
                (false, false) => match (self.is_prerelease, other.is_prerelease) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => self.suffix.cmp(&other.suffix),
                },
            }
        })
    }
}

impl PartialOrd for VersionSegment {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Compare two version strings segment by segment.
///
/// Rules:
/// - Split on '.' into segments
/// - Each segment: numeric prefix compared numerically, then suffix
/// - No suffix (1.10) > letter suffix (1.10a) > pre-release (1.10-beta)
/// - Fewer segments < more segments if prefix is equal (1.0 < 1.0.1)
fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let a_parts: Vec<VersionSegment> = a.split('.').map(VersionSegment::parse).collect();
    let b_parts: Vec<VersionSegment> = b.split('.').map(VersionSegment::parse).collect();
    a_parts.cmp(&b_parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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

    #[test]
    fn version_ordering_basic() {
        assert_eq!(version_cmp("1.0", "2.0"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.9", "1.10"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("2.0", "2.0"), std::cmp::Ordering::Equal);
        assert_eq!(version_cmp("1.0", "1.0.1"), std::cmp::Ordering::Less);
    }

    #[test]
    fn version_ordering_suffixes() {
        // No suffix > letter suffix
        assert_eq!(version_cmp("1.10", "1.10a"), std::cmp::Ordering::Greater);
        assert_eq!(version_cmp("1.10a", "1.10b"), std::cmp::Ordering::Less);
    }

    #[test]
    fn version_ordering_prerelease() {
        // No suffix > pre-release
        assert_eq!(version_cmp("1.10", "1.10-beta"), std::cmp::Ordering::Greater);
        assert_eq!(version_cmp("1.10-alpha", "1.10-beta"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.10-beta", "1.10"), std::cmp::Ordering::Less);
        // Letter suffix > pre-release
        assert_eq!(version_cmp("1.10a", "1.10-beta"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn version_ordering_mixed() {
        // 1.9 < 1.10-beta < 1.10a < 1.10b < 1.10 < 1.10.1
        let mut versions = vec!["1.10b", "1.10-beta", "1.9", "1.10.1", "1.10", "1.10a"];
        versions.sort_by(|a, b| version_cmp(a, b));
        assert_eq!(versions, vec!["1.9", "1.10-beta", "1.10a", "1.10b", "1.10", "1.10.1"]);
    }
}
