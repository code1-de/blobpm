use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub description: String,
    pub files: BTreeMap<String, String>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PackageVersion {
    pub version: String,
    pub path: PathBuf,
    pub manifest: Manifest,
}

#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub latest: String,
    pub versions: Vec<String>,
}

#[derive(Debug)]
pub struct RepoIndex {
    pub packages: BTreeMap<String, PackageInfo>,
    repo_path: PathBuf,
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
            return Ok(Self {
                packages,
                repo_path: repo_path.to_path_buf(),
            });
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
                let manifest_path = ver_entry.path().join("blob.json");
                if manifest_path.is_file() {
                    versions.push(ver);
                }
            }

            if versions.is_empty() {
                continue;
            }

            versions.sort_by(|a, b| version_cmp(a, b));

            let latest = versions.last().unwrap().clone();
            packages.insert(
                pkg_name.clone(),
                PackageInfo {
                    name: pkg_name,
                    latest,
                    versions,
                },
            );
        }

        Ok(Self {
            packages,
            repo_path: repo_path.to_path_buf(),
        })
    }

    /// Load the manifest for a specific package version.
    ///
    /// # Errors
    /// Returns an error if the manifest file cannot be read or parsed.
    pub fn load_manifest(&self, name: &str, version: &str) -> io::Result<PackageVersion> {
        let manifest_path = self
            .repo_path
            .join("packages")
            .join(name)
            .join(version)
            .join("blob.json");

        let content = fs::read_to_string(&manifest_path)?;
        let manifest: Manifest = serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let path = manifest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();

        Ok(PackageVersion {
            version: version.to_string(),
            path,
            manifest,
        })
    }

    pub fn package_file_path(&self, name: &str, version: &str, file: &str) -> PathBuf {
        self.repo_path
            .join("packages")
            .join(name)
            .join(version)
            .join(file)
    }

    /// Build a summary index mapping package names to their latest version.
    #[must_use]
    pub fn index_summary(&self) -> BTreeMap<String, String> {
        self.packages
            .iter()
            .map(|(name, info)| (name.clone(), info.latest.clone()))
            .collect()
    }
}

/// Compare two version strings by splitting on '.' and comparing each part numerically.
fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let a_parts: Vec<u64> = a.split('.').filter_map(|s| s.parse().ok()).collect();
    let b_parts: Vec<u64> = b.split('.').filter_map(|s| s.parse().ok()).collect();
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
            pkg_dir.join("blob.json"),
            r#"{"name":"testpkg","description":"A test package","files":{"test.exe":"util/"},"dependencies":[]}"#,
        )
        .unwrap();

        let pkg_dir2 = base.join("packages").join("testpkg").join("2.0");
        fs::create_dir_all(&pkg_dir2).unwrap();
        fs::write(
            pkg_dir2.join("blob.json"),
            r#"{"name":"testpkg","description":"A test package v2","files":{"test.exe":"util/"},"dependencies":[]}"#,
        )
        .unwrap();

        let other_dir = base.join("packages").join("other").join("0.1");
        fs::create_dir_all(&other_dir).unwrap();
        fs::write(
            other_dir.join("blob.json"),
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
    fn load_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());

        let index = RepoIndex::scan(tmp.path()).unwrap();
        let pkg = index.load_manifest("testpkg", "2.0").unwrap();
        assert_eq!(pkg.manifest.name, "testpkg");
        assert_eq!(pkg.version, "2.0");
        assert_eq!(pkg.manifest.files["test.exe"], "util/");
    }

    #[test]
    fn index_summary() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());

        let index = RepoIndex::scan(tmp.path()).unwrap();
        let summary = index.index_summary();
        assert_eq!(summary["testpkg"], "2.0");
        assert_eq!(summary["other"], "0.1");
    }

    #[test]
    fn version_ordering() {
        assert_eq!(version_cmp("1.0", "2.0"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.9", "1.10"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("2.0", "2.0"), std::cmp::Ordering::Equal);
    }
}
