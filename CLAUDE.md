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

(General Rust rules — quality gate, error handling, imports, debug build — live in the global `CLAUDE.md`.)

- Each phase must compile and work (as far as implemented).
- Run the Rust quality gate **before every commit**, not only at the end of a work block.

## Security

(General rules — validate untrusted input, path-traversal defense in depth, disk ops only after validation, security tests at every boundary — live in the global `CLAUDE.md`.) Blob-specific trust boundaries:

- Untrusted input arrives via: HTTP requests, manifests, config files, package zips, CLI args.
- Server side: **no arbitrary file reads from user-supplied paths** — always confine to the repo directory. Clients confine extraction to `base_dir`/`path_map`.

## Conventions

(General conventions — no-hand-rolled-FFI, import grouping, DRY, discuss-before-big-refactors, no-auto-commit, no `cd`/`git -C` in the cwd — live in the global `CLAUDE.md`.)

- Keep it simple — this is a personal tool.
- No async where not needed (server is async, client can be blocking).
- Manifest file is called `manifest.json`.
- The shim (`shim/`) is a deliberate exception to the no-hand-rolled-FFI rule: it is `#![no_std]` and cannot pull in the `windows` crate.
- **Before committing:** if a `PLAN.md` exists (it lives in the maintainer's private overlay repo, see below), review and update it — check off completed items, add new items if needed.

## Private overlay repo (maintainer-only)

This working directory hosts two git repos sharing one tree:

- `.git/` — the public repo (this one). Tracks source, docs, and configs.
- `.git-private/` — a private overlay with personal scripts, `PLAN.md`, `docker/`, `.claude/`, and local configs. Invoked via the `gip.bat` wrapper (`gip status`, `gip log`, etc.). Not present in public clones.

Public clones do not see `.git-private/` or `gip.bat`. Contributors can ignore this section; it only matters on the maintainer's machine.
