use std::io;

use crate::client::{Database, InstallReason};

fn reverse_deps(name: &str, db: &Database) -> Vec<String> {
    db.packages.iter().filter(|(_, pkg)| pkg.dependencies.contains(&name.to_string())).map(|(n, _)| n.clone()).collect()
}

// TODO: build reverse-dep index for O(n) lookup instead of O(n²) per iteration
pub(crate) fn purge_orphans(db: &mut Database) -> io::Result<()> {
    loop {
        let orphans: Vec<String> = db
            .packages
            .iter()
            .filter(|(_, pkg)| pkg.reason == InstallReason::Auto)
            .filter(|(dep_name, _)| !db.packages.iter().any(|(_, p)| p.dependencies.contains(dep_name)))
            .map(|(n, _)| n.clone())
            .collect();

        if orphans.is_empty() {
            break;
        }

        for orphan in &orphans {
            println!("Removing orphaned dependency {orphan}...");
            remove_package_files(orphan, db)?;
        }
    }
    Ok(())
}

pub fn purge(db: &mut Database) -> io::Result<()> {
    let before = db.packages.len();
    purge_orphans(db)?;
    let removed = before - db.packages.len();
    if removed == 0 {
        println!("No orphaned packages found.");
    } else {
        println!("Purged {removed} orphaned package{}.", crate::util::plural(removed));
    }
    db.save()
}

fn remove_package_files(name: &str, db: &mut Database) -> io::Result<()> {
    let Some(pkg) = db.packages.get(name) else {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{name} is not installed")));
    };

    for (file, path) in &pkg.files {
        if path.is_file() {
            std::fs::remove_file(path)?;
            println!("  Removed {file} ({})", path.display());
        }
    }

    db.packages.remove(name);
    Ok(())
}

pub fn remove(name: &str, force: bool, transitive: bool, no_purge: bool, db: &mut Database) -> io::Result<()> {
    if !db.packages.contains_key(name) {
        if transitive {
            return Ok(()); // already removed by cascade
        }
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{name} is not installed")));
    }

    // Check reverse dependencies
    let rdeps = reverse_deps(name, db);
    if !rdeps.is_empty() && !force && !transitive {
        eprintln!("Cannot remove {name}: depended on by:");
        for dep in &rdeps {
            eprintln!("  {dep}");
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Use --force to override, or --transitive to also remove dependents.".to_string(),
        ));
    }

    // --transitive: remove dependents first (upward cascade)
    if transitive {
        for rdep in &rdeps {
            remove(rdep, false, true, true, db)?;
        }
    }

    // Already removed by transitive cascade
    if !db.packages.contains_key(name) {
        return Ok(());
    }

    println!("Removing {name}...");
    remove_package_files(name, db)?;

    if !no_purge {
        purge_orphans(db)?;
        db.save()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Config, HttpClient};
    use crate::install::install;
    use crate::testutil::helpers::{TEST_PASS, TEST_USER, create_zip, start_tls_server};
    use std::path::Path;

    fn create_test_repo(base: &Path) {
        let pkg_dir = base.join("packages").join("toolA").join("1.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("manifest.json"),
            r#"{"name":"toolA","description":"Tool A","files":{"toolA.exe":"util/"},"dependencies":[]}"#,
        )
        .unwrap();
        create_zip(&pkg_dir, &[("toolA.exe", b"toolA-binary")]);

        let pkg_dir2 = base.join("packages").join("toolB").join("2.0");
        std::fs::create_dir_all(&pkg_dir2).unwrap();
        std::fs::write(
            pkg_dir2.join("manifest.json"),
            r#"{"name":"toolB","description":"Tool B","files":{"toolB.exe":"util/"},"dependencies":["toolA"]}"#,
        )
        .unwrap();
        create_zip(&pkg_dir2, &[("toolB.exe", b"toolB-binary")]);
    }

    fn test_config(port: u16, base_dir: &Path, fingerprint: &str) -> Config {
        Config {
            server_url: format!("https://localhost:{port}"),
            base_dir: base_dir.to_path_buf(),
            username: TEST_USER.to_string(),
            password: TEST_PASS.to_string(),
            server_fingerprint: fingerprint.to_string(),
            cache_days: 0,
            path_map: std::collections::BTreeMap::new(),
            cache_dir: Some(base_dir.join(".cache")),
        }
    }

    fn create_diamond_repo(base: &Path) {
        for (name, ver, deps, file) in [
            ("depA", "1.0", "[]", "depA.exe"),
            ("depB", "1.0", r#"["depA"]"#, "depB.exe"),
            ("depC", "1.0", r#"["depB"]"#, "depC.exe"),
            ("depD", "1.0", r#"["depB"]"#, "depD.exe"),
        ] {
            let dir = base.join("packages").join(name).join(ver);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("manifest.json"),
                format!(r#"{{"name":"{name}","description":"","files":{{"{file}":"util/"}},"dependencies":{deps}}}"#),
            )
            .unwrap();
            create_zip(&dir, &[(file, format!("{name}-{ver}-binary").as_bytes())]);
        }
    }

    #[test]
    fn remove_simple_package() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolA", None, false, false, false, &http, &mut db).unwrap();
        assert!(install_tmp.path().join("util").join("toolA.exe").exists());

        remove("toolA", false, false, false, &mut db).unwrap();
        assert!(!install_tmp.path().join("util").join("toolA.exe").exists());
        assert!(!db.packages.contains_key("toolA"));
    }

    #[test]
    fn remove_blocked_by_dependent() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolB", None, false, false, false, &http, &mut db).unwrap();

        let result = remove("toolA", false, false, false, &mut db);
        assert!(result.is_err());
        assert!(db.packages.contains_key("toolA"));
    }

    #[test]
    fn remove_force_ignores_dependents() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolB", None, false, false, false, &http, &mut db).unwrap();

        remove("toolA", true, false, false, &mut db).unwrap();
        assert!(!db.packages.contains_key("toolA"));
        assert!(db.packages.contains_key("toolB"));
    }

    #[test]
    fn remove_auto_cleans_orphans() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolB", None, false, false, false, &http, &mut db).unwrap();
        assert_eq!(db.packages["toolA"].reason, InstallReason::Auto);

        remove("toolB", false, false, false, &mut db).unwrap();
        assert!(!db.packages.contains_key("toolB"));
        assert!(!db.packages.contains_key("toolA"));
        assert!(!install_tmp.path().join("util").join("toolA.exe").exists());
        assert!(!install_tmp.path().join("util").join("toolB.exe").exists());
    }

    #[test]
    fn remove_keeps_manual_deps() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolB", None, false, false, false, &http, &mut db).unwrap();
        install("toolA", None, false, false, false, &http, &mut db).unwrap();
        assert_eq!(db.packages["toolA"].reason, InstallReason::Manual);

        remove("toolB", false, false, false, &mut db).unwrap();
        assert!(!db.packages.contains_key("toolB"));
        assert!(db.packages.contains_key("toolA"));
    }

    #[test]
    fn remove_transitive_cascades_upward() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolB", None, false, false, false, &http, &mut db).unwrap();

        remove("toolA", false, true, false, &mut db).unwrap();
        assert!(!db.packages.contains_key("toolA"));
        assert!(!db.packages.contains_key("toolB"));
    }

    #[test]
    fn remove_nonexistent_package_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.json");
        let mut db = Database::load_from(&db_path).unwrap();

        let result = remove("nonexistent", false, false, false, &mut db);
        assert!(result.is_err());
    }

    #[test]
    fn diamond_remove_one_branch_keeps_shared_dep() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_diamond_repo(repo_tmp.path());
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("depC", None, false, false, false, &http, &mut db).unwrap();
        install("depD", None, false, false, false, &http, &mut db).unwrap();

        remove("depC", false, false, false, &mut db).unwrap();
        assert!(!db.packages.contains_key("depC"));
        assert!(db.packages.contains_key("depB"));
        assert!(db.packages.contains_key("depA"));
    }

    #[test]
    fn diamond_remove_both_branches_cleans_all() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_diamond_repo(repo_tmp.path());
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("depC", None, false, false, false, &http, &mut db).unwrap();
        install("depD", None, false, false, false, &http, &mut db).unwrap();

        remove("depC", false, false, false, &mut db).unwrap();
        remove("depD", false, false, false, &mut db).unwrap();
        assert!(db.packages.is_empty());
    }

    #[test]
    fn transitive_remove_with_diamond() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_diamond_repo(repo_tmp.path());
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("depC", None, false, false, false, &http, &mut db).unwrap();
        install("depD", None, false, false, false, &http, &mut db).unwrap();

        remove("depA", false, true, false, &mut db).unwrap();
        assert!(db.packages.is_empty());
    }
}
