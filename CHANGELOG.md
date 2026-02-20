# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.1.0] - 2026-02-19

### Added
- `--compat` flag: ASCII-only borders (`+`, `-`, `|`) and 16-color ANSI
  styles for RMM consoles and restricted terminal environments that cannot
  render Unicode box-drawing characters or 24-bit color.
- `Compat` struct in `src/ui/theme.rs` with ASCII symbol constants
  (`SYM_ONLINE`, `SYM_OFFLINE`, `SYM_CURSOR`, etc.) and 16-color style helpers.
- `.compat(bool)` builder method on all TUI widgets (`ScanTable`,
  `ProgressBar`, `InputBar`, `DetailsPane`, `StatusBar`).
- `compat: bool` field on `Config` and `App`.
- Mouse capture, Kitty keyboard enhancement protocol, and the Ctrl
  keybindings popup are disabled in compat mode.

---

## [1.0.0] - 2026-02-19

### Added
- Initial release.
- Adaptive TUI with `Compact` (< 100×30) and `Full` split-pane layouts,
  powered by ratatui + crossterm.
- Host discovery via TCP connect probes to 30+ common ports — no raw
  ICMP sockets or administrator privileges required.
- ICMP ping as primary detection method with TCP fallback
  (`PingMethod::Icmp` / `PingMethod::Tcp`).
- Async port scanning with semaphore-limited concurrency (default 50).
- Reverse DNS resolution with in-memory caching.
- ARP-based MAC address retrieval with embedded OUI vendor database
  (~17 000 entries; no internet access required).
- Persistent scan cache (`ipscannr_cache.json`), keyed by IP range;
  `IPSCANNR_CACHE_FILE` env var overrides the path.
- CSV export of scan results from inside the TUI.
- Continuous ping overlay with live stdout streaming.
- Tracert overlay with live stdout streaming.
- Wake-on-LAN: send magic packets to selected hosts.
- `--range` and `--scan` CLI flags for non-interactive / scripted use.
- `Tab` / `Shift+Tab` pane cycling.
- Mouse support (click to focus panes, scroll table).
- Windows `.ico` icon embedded in the binary via `winres`.
- MIT license.

[Unreleased]: https://github.com/DailenG/ipscannr/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/DailenG/ipscannr/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/DailenG/ipscannr/releases/tag/v1.0.0
