# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
# Debug build and run
cargo run

# Run with CLI args (auto-start scan on a range)
cargo run -- --range 192.168.1.0/24 --scan

# Compatibility mode (ASCII-only, for RMM consoles / limited environments)
cargo run -- --compat
cargo run -- --range 192.168.1.0/24 --scan --compat

# Release build
cargo build --release

# Check for compile errors without building
cargo check

# Lint with clippy
cargo clippy

# Format code
cargo fmt
```

## Engineering Practices (Required)

### Commit discipline
- Make **small, atomic commits** for each logical change (one fix/refactor/test unit at a time).
- Commit frequently after each passing validation gate.
- Keep commit messages scoped and explicit (`scope: intent` + short rationale).
- Prefer revert-friendly history over large bundled changes.

### Validation gates (run continuously)
- Fast gate: `cargo check`
- Focused gate: run tests for touched modules first (for example `cargo test cache::tests`)
- Broader gate: `cargo test`
- Quality gate: `cargo clippy`
- Build gate: `cargo build --release` at phase boundaries and before handoff
- Formatting: repository currently contains pre-existing rustfmt drift; avoid broad formatting-only edits unless explicitly doing a formatting pass.

### Testing expectations
- Add tests alongside behavior changes, especially for parser logic, cache semantics, and async control flow.
- Prefer deterministic unit tests for state transitions and pure functions.
- For async flows, test cancellation/closure behavior and timeout paths.
- Re-run tests after every non-trivial refactor to catch regressions early.

### Reliability and performance safeguards
- Avoid unbounded task fan-out; use bounded worker pools or explicit concurrency limits.
- Avoid panics in runtime paths (`unwrap`/`expect`) unless invariants are provably guaranteed.
- Favor durable file-write patterns for persisted state (temp file + replace semantics).
- Treat pause/resume/cancel paths as high-risk and validate them explicitly after edits.

## Semantic Versioning

Version is defined in `Cargo.toml` only — clap reads it automatically via `#[command(version)]`.

### Rules (required)
- **PATCH** `1.0.x` — bug fixes, cosmetic/display changes, internal refactors with no
  user-visible behavior change. Bump before the commit that fixes the bug.
- **MINOR** `1.x.0` — new features, new CLI flags, new modes, new capabilities added
  without removing existing ones. Bump before the commit that adds the feature.
- **MAJOR** `x.0.0` — breaking changes to CLI interface, removal of existing flags/features,
  or fundamental behavioral overhaul. Discuss before bumping.

### Workflow
- Bump `Cargo.toml` in the **same commit** as (or immediately before) the change that
  warrants the bump.
- Never let multiple features accumulate under one unreleased version bump.
- The version visible via `ipscannr --version` must always reflect the current binary.

## Architecture Overview

**ipscannr** is a terminal-based network scanner (TUI) written in Rust using `ratatui` + `crossterm` for UI and `tokio` for async concurrency.

### Entry Point & Event Loop

`src/main.rs` owns the terminal lifecycle and the main `tokio::select!` event loop. It drives four concurrent streams:
- Keyboard input (polled every 50ms via crossterm)
- Background adapter loading (one-shot task at startup)
- Scan events streamed over `mpsc` from scanner tasks
- Overlay output (continuous ping / tracert stdout lines)

All UI rendering happens in `draw_ui()` inside `main.rs`, calling individual draw functions for each pane.

### Application State

`src/app.rs` (`App` struct, ~1100 lines) is the central state machine. Key state:
- `InputMode` — controls active key bindings (Normal, EditingRange, EditingPorts, Help, Exporting, OutputOverlay)
- `ScanState` — scan lifecycle (Idle → Scanning → Paused → Completed)
- `Focus` — which pane receives navigation keys (RangeInput, HostsTable, DetailsPane)
- `FilterMode` — All vs. OnlineOnly

`app.handle_action()` dispatches `Action` variants produced by `src/input.rs`.

### Scanner Modules (`src/scanner/`)

| File | Responsibility |
|------|---------------|
| `adapters.rs` | Network interface detection (platform-specific: `ipconfig` on Windows, `/sys/class/net/` on Linux) |
| `ping.rs` | Host discovery via TCP connect to common ports (80, 443, 22, 445 …) — no ICMP/root required |
| `port.rs` | Async port scanning with semaphore-based concurrency |
| `dns.rs` | Async reverse DNS with caching |
| `mac.rs` | ARP-based MAC retrieval + embedded OUI vendor database (~17k entries) |
| `range.rs` | Parses CIDR, `x.x.x.x-y`, `x.x.x.x-x.x.x.x`, single IP, and comma-separated formats |

Scan results are streamed via `mpsc` channels; cancellation uses a dedicated cancel-sender.

### UI System (`src/ui/`)

- `layout.rs` — Switches between `Compact` (< 100×30) and `Full` layouts; Full adds a 55/45 split with a Details pane.
- `theme.rs` — Centralizes all colors (dark bg `#121218`, cornflower-blue accent, green/red status).
- `widgets/` — Custom ratatui widgets: `ScanTable`, `DetailsPane`, `InputBar`, `ProgressBar`, `StatusBar`.

### Caching (`src/cache.rs`)

Scan results are persisted to `ipscannr_cache.json` (keyed by IP range). Cache is loaded at startup so results are immediately visible before a new scan runs.

### Key Design Patterns

- **Message-passing concurrency**: all background tasks communicate via `tokio::sync::mpsc` channels; no shared mutable state across tasks.
- **State machine input handling**: `src/input.rs` maps `KeyEvent → Action` based on the current `InputMode`; `app.handle_action()` dispatches on `Action`.
- **Semaphore-limited concurrency**: ping and port scanners use `tokio::sync::Semaphore` to cap concurrent connections (default 100 for ping, 50 for ports).
- **Embedded data**: the OUI vendor database lives entirely in `mac.rs` — no runtime downloads.
