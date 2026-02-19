# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
# Debug build and run
cargo run

# Run with CLI args (auto-start scan on a range)
cargo run -- --range 192.168.1.0/24 --scan

# Release build
cargo build --release

# Check for compile errors without building
cargo check

# Lint with clippy
cargo clippy

# Format code
cargo fmt
```

There is no test suite — the project relies on manual TUI testing.

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
