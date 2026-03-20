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

## Conventions

- Keep it simple — this is a personal tool
- No async where not needed (server is async, client can be blocking)
- Manifest file is called `blob.json`
