# Blob Package Manager

## Why Another Package Manager?

The honest answer is: I wanted to have one, and I wanted to build it myself in Rust, using an AI coding agent (Claude Code). That said, it has several design principles that I think other package managers don't have:

- **Single executable.** One binary contains all client and server code. You can carry around this one executable and connect to your repository of programs.
- **Easy self-hosting.** All you need is a machine reachable via TCP/IP. No Apache, git, or nuget needed; batteries included.
- **Flat installation.** Multiple packages can be installed into the same directory. This was important to me because I have one directory with assorted utility programs collected over the years. I didn't want hardlinks, symlinks, or shims — just the proper executables, directly there.
- **Shims when needed.** For larger tools you can still use shims. For example, IrfanView can live in its own directory with all its files, while a small shim in the utility directory calls the actual `i_view64.exe`, thus allowing it to find its other files.
- **Simple security like SSH.** On first connection you approve the server's certificate fingerprint and henceforth trust that connection. On the server side, you don't need anything but a self-signed certificate, which the server executable generates on first use.
- **Simple uploads.** A single command-line call uploads a file, a set of files, or a whole directory tree to the server and creates the matching manifest automatically.

## Features

### Package Management

- **Install, remove, update** packages with a single command
- **Dependency resolution** with cycle detection – installing a package automatically pulls in its dependencies
- **Orphan cleanup** – removing a package also removes auto-installed dependencies that are no longer needed
- **Conflict detection** – prevents two packages from overwriting each other's files (override with `--overwrite`)
- **Specific versions** – install any version with `name@version` syntax
- **Meta-packages** – packages with no files, only dependencies (useful for bundles like "devtools")
- **Download cache** – downloads are cached locally; reinstalls and updates skip downloads when the cache is fresh
- **Self-update** – blob can update its own binary (renames the running exe, writes the new one, spawns a cleanup process)
- **Manual marking** – auto-installed dependencies can be marked as manually installed (`blob manual`), preventing them from being auto-removed
- **Non-interactive mode** (`--yes`) for scripting and automation

### Server

- **Single binary** – the same `blob` executable runs as a server (`blob serve`) or as a client
- **HTTPS-only** with auto-generated self-signed certificates
- **Role-based access** – `admin` (read + write) and `reader` (read-only) users
- **Upload with validation** – server cross-validates zip contents against the manifest, rejects unsafe paths
- **Rate limiting** – per-IP connection limits, exponential backoff on failed auth, global concurrency cap
- **Request timeout** and upload size limits (512 MB)
- **Structured logging** to stdout and optional log file

### Security

- **Trust On First Use (TOFU)** – like SSH, the client remembers the server's certificate fingerprint on first connection and warns if it changes
- **Path safety** – all paths from manifests, uploads, and URLs are validated against traversal attacks (`..`), absolute paths, null bytes, and Windows reserved device names
- **Confinement** – extracted files are canonicalized and verified to stay inside their allowed root directory
- **Zip bomb protection** – per-file (1 GB), total (2 GB), and entry count (200k) limits on extraction
- **Constant-time credential comparison** to prevent timing attacks
- **Owner-only file permissions** on config and database files (Windows ACLs / Unix 0600)

### Shim Links

Packages can define **shim links**: lightweight launcher executables (4.5 KB, `no_std`) that redirect to the real binary via a relative path. Unlike hard links or symlinks, the target process sees its real directory (not the shim's), so tools that locate resources relative to their own exe work correctly. This lets you put a single `bin/` directory on your PATH while the actual tools live in deeper directory trees. Shims auto-detect GUI subsystem from the target PE. Currently Windows 64-bit only.

### Path Mapping

The `path_map` configuration lets manifest destination directories route to different local paths. For example, map `bin` to `D:\tools\bin` while everything else goes to the default base directory. Useful when tools need to live on specific drives or in specific locations.

## Installation

### From source

```cmd
cargo build --release
```

The binary is at `target/release/blob.exe`.


## Quick Start

### Server setup

1. Generate TLS certificates:

   ```cmd
   blob generate-keys
   ```

2. Create a server config file `server.json`:

   ```json
   {
     "repo": "C:\\my-repo",
     "bind": "0.0.0.0",
     "port": 53777,
     "log": "C:\\my-repo\\blob.log",
     "users": [
       { "username": "admin", "password": "secret", "role": "admin" },
       { "username": "ci", "password": "readonly", "role": "reader" }
     ]
   }
   ```

3. Start the server:

   ```cmd
   blob serve server.json
   ```

### Client setup

```cmd
blob config
```

This interactively configures the server URL, install directory, credentials, and path mappings. On first connection, you'll be prompted to trust the server's certificate fingerprint.

### Common commands

```cmd
# Install a package (latest version)
blob install fd

# Install a specific version
blob install fd@10.2.0

# Install multiple packages
blob install fd ripgrep bat

# Update all packages
blob update

# Update a single package
blob update fd

# Check what would be updated
blob update --dry-run

# Remove a package (auto-removes orphaned deps)
blob remove fd

# Remove a package and everything that depends on it
blob remove openssl --transitive

# List installed packages
blob list

# List only manually installed packages
blob list --manual

# Show details of an installed package
blob list fd

# Search for packages on the server
blob search "^fd"

# Search in descriptions too
blob search "file search" --description

# Show remote package details
blob info fd

# Upload a package
blob upload mytool@1.0 "*.exe:bin" --dep openssl -d "My tool"

# Upload with interactive review
blob upload mytool@1.0 "*.exe:bin" --interactive

# Upload a meta-package (no files, only deps)
blob upload devtools@1.0 --dep fd --dep ripgrep --dep bat -d "Dev bundle"

# Show which files in a directory are managed by blob
blob status C:\tools

# Delete a version from the server
blob delete mytool@1.0

# Clean the download cache
blob clean-cache

# Clean leftover files from in-use renames
blob cleanup
```

## Architecture

### Overview

```
blob (single binary)
  │
  ├── client (reqwest, blocking)
  │     ├── config.json     (~/.blob/)
  │     ├── db.json         (~/.blob/)
  │     └── cache/          (~/.blob/cache/<name>/<version>/files.zip)
  │
  └── server (axum, async, feature-gated)
        ├── packages/<name>/<version>/manifest.json
        └── packages/<name>/<version>/files.zip
```

The server scans its `packages/` directory on startup and re-scans after uploads and deletes. The client stores its state in `~/.blob/`.

### Manifest format

Each package version has a `manifest.json`:

```json
{
  "name": "fd",
  "description": "A simple, fast alternative to find",
  "files": {
    "fd.exe": "bin",
    "README.md": "doc/fd"
  },
  "dependencies": ["vcruntime"],
  "links": {
    "bin/find.exe": "fd/fd.exe"
  }
}
```

- **files** maps filenames inside the zip to destination directories (relative to `base_dir` or `path_map`)
- **dependencies** are other package names (always resolved to latest version)
- **links** (optional) create shim executables: the key is where the shim goes, the value is what it launches

### Local database

`db.json` tracks installed packages:

```json
{
  "packages": {
    "fd": {
      "version": "10.2.0",
      "reason": "manual",
      "files": {
        "fd.exe": "C:\\tools\\bin\\fd.exe"
      },
      "dependencies": []
    }
  }
}
```

The `reason` field is either `manual` (user installed it) or `auto` (pulled in as a dependency). Auto-installed packages are removed when no longer needed.

### Server API

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/index` | any | Package index (name -> latest version, description) |
| GET | `/packages/{name}` | any | Available versions for a package |
| GET | `/packages/{name}/{version}/{file}` | any | Download manifest or zip |
| POST | `/upload/{name}/{version}/{file}` | admin | Upload manifest (first) or zip (second) |
| DELETE | `/packages/{name}/{version}` | admin | Delete a package version |

### Upload mappings

The `upload` command uses glob patterns to map local files into the package:

```cmd
# Single glob → destination
blob upload tool@1.0 "*.exe:bin"

# Multiple files sharing a destination
blob upload tool@1.0 "app.exe;app.dll:bin"

# Relative glob preserves directory structure
blob upload tool@1.0 "share/**:data"

# Absolute glob uses filename only
blob upload tool@1.0 "C:\build\output\*.exe:bin"

# Multiple mappings (first match wins)
blob upload tool@1.0 "*.exe:bin" "*.dll:lib" "*.chm:doc"
```

### Version ordering

Versions are dot-separated numeric segments with an optional qualifier (letter suffix or pre-release tag) that applies to the whole version. Trailing `.0` segments are ignored (`1.0` == `1.0.0`). Comparison is case-insensitive (`-BETA` == `-beta`).

Ordering for a given base version:

```
pre-release (-alpha, -beta, -rc) < plain < letter suffix (a, b, c)

1.9 < 1.10-alpha < 1.10-beta < 1.10-beta2 < 1.10-beta12 < 1.10 < 1.10a < 1.10b < 1.10.1
```

Pre-release numbers are compared numerically (`-beta2 < -beta12`), not lexicographically. Letter suffixes denote post-release patches (like OpenSSL's `1.0.1a`).

On upload, versions are canonicalized: trailing `.0` segments are stripped and suffixes lowercased (`1.0.0-BETA` → `1-beta`). A warning is shown if the uploaded version is older than the existing latest.

### Module structure

| Module | Role |
|--------|------|
| `main.rs` | CLI (clap), subcommand dispatch |
| `server.rs` | axum HTTPS server, auth, rate limiting, upload validation |
| `install.rs` | Install, update, dependency resolution, zip extraction, cache |
| `upload.rs` | Package creation, glob mapping, search |
| `platform.rs` | OS abstraction: path normalization, file permissions, in-use rename |
| `client.rs` | Config, database, HTTP client, input validation |
| `remove.rs` | Package removal, orphan cleanup, reverse-dep checks |
| `tls.rs` | TOFU cert verification, self-signed cert generation |
| `repo.rs` | Manifest/index types, repo scanning, version comparison |
| `shim.rs` | Shim exe creation (Windows 64-bit, GUI auto-detect) |
| `testutil.rs` | Test helpers (zip creation, TLS test server) |
| `util.rs` | Pluralization, ANSI color |

The `server` feature is compile-time optional (`--no-default-features` excludes `server.rs` and its async dependencies).

### Shim binary

The `shim/` subdirectory contains a separate `no_std` Rust project that compiles to a 4.5 KB Windows executable. It reads a relative target path appended to its own PE image, resolves it against its own directory, and launches the target with the original command-line arguments. The main blob binary embeds this shim and writes customized copies when creating link entries.

## Development

```cmd
# Run tests
cargo test

# Run clippy
cargo clippy --all-targets -- -W clippy::all -W clippy::pedantic

# Format
cargo fmt
```

Tests include both unit tests and integration tests. Integration tests spin up ephemeral TLS servers with test credentials and exercise the full client-server flow (install, remove, update, upload, conflict detection, dependency resolution, etc.).

## Configuration reference

### Client config (`~/.blob/config.json`)

| Field | Description |
|-------|-------------|
| `server_url` | Server URL (must be `https://`) |
| `base_dir` | Default install root for packages |
| `username` | HTTP basic auth username |
| `password` | HTTP basic auth password |
| `server_fingerprint` | Saved TLS certificate fingerprint (auto-populated on first connect) |
| `cache_days` | Days to keep cached downloads (0 = no cache, default: 1) |
| `path_map` | Map dest dir prefixes to local paths (e.g. `{"bin": "D:\\tools\\bin"}`) |

### Server config

| Field | Default | Description |
|-------|---------|-------------|
| `repo` | (required) | Path to the package repository |
| `bind` | `127.0.0.1` | Bind address |
| `port` | `53777` | Listen port |
| `log` | (none) | Optional log file path |
| `users` | (required) | List of `{username, password, role}` entries |

### Server limits

| Limit | Value |
|-------|-------|
| Max upload size | 512 MB |
| Max concurrent connections | 20 |
| Max connections per IP | 10 |
| Auth lockout threshold | 5 failures |
| Auth lockout range | 30s – 1h (exponential) |
| Request timeout | 600s |

### Extraction limits

| Limit | Value |
|-------|-------|
| Max file size (per file) | 1 GB |
| Max total extraction size | 2 GB |
| Max zip entries | 200,000 |

## License

MIT
