# Blob

Windows user-mode package manager. One Rust binary, acts as both server and client.

## Build & Run

```
cargo build
cargo run -- serve --repo <path>
cargo run -- install <pkg>
```

## Project Structure

- Single binary with clap subcommands: `serve`, `install`, `remove`, `update`, `list`
- Server: axum, scans repo directory on startup
- Client: reqwest for HTTP, serde_json for manifests and local DB
- Local state in `~/.blob/` (config.json, db.json)

## Quality

- Each phase must compile and work (as far as implemented)
- Tests for every new feature: `cargo test`
- Lint clean: `cargo clippy --all-targets -- -W clippy::all -W clippy::pedantic`
- All clippy warnings must be fixed
- Default build is debug (`cargo build`), not release
- Production-grade error handling: no `unwrap()` or `expect()` in non-test code
- All errors must be propagated gracefully with `?` or proper error messages

## Security

- **Never trust external input.** All data from HTTP requests, manifests, config files, and user input must be validated before use.
- **Path safety:** Any path assembled from external strings must be validated — reject `..`, absolute paths, drive letters (`:`), UNC paths. Always verify the resolved path stays inside the expected root directory.
- **Defense in depth:** Validate inputs early (allowlist checks), then verify the result (canonicalize + starts_with). Never rely on a single check.
- **Disk operations after validation:** Never create files/directories before verifying the target path is permitted.
- **No arbitrary file reads from user-supplied paths** on the server side — always confine to the repo directory.
- **Write security tests** for every boundary that accepts external input (path traversal, absolute paths, special characters).

## Conventions

- Keep it simple — this is a personal tool
- No async where not needed (server is async, client can be blocking)
- Manifest file is called `manifest.json`
- DRY: Don't repeat yourself — extract shared logic into functions, never duplicate code
- **No big refactors without asking first.** Discuss architectural changes before implementing them.
- **No automatic commits or pushes.** Only commit or push when the user explicitly asks.
