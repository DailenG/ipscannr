# ipscannr

[![CI](https://github.com/DailenG/ipscannr/actions/workflows/ci.yml/badge.svg)](https://github.com/DailenG/ipscannr/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/DailenG/ipscannr)](https://github.com/DailenG/ipscannr/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A terminal-based IP scanner with an adaptive TUI — scan your local network,
identify live hosts, enumerate open ports, resolve hostnames, and look up MAC
vendor info, all without leaving the terminal.

> **Platform:** Windows only. Host discovery and adapter detection use
> PowerShell and ARP via Windows tooling.

---

## Features

- **Adaptive TUI** — full split-pane layout on large terminals; compact
  single-pane layout on smaller windows, powered by [ratatui].
- **No admin required** — host discovery uses TCP connect probes to common
  ports instead of raw ICMP sockets.
- **Port scanning** — async, semaphore-limited (default 50 concurrent).
- **Reverse DNS** — async resolution with in-memory caching.
- **MAC + OUI vendor lookup** — ARP-based with an embedded ~17 000-entry
  vendor database; no internet required.
- **Persistent cache** — results written to `ipscannr_cache.json` and
  loaded on next launch.
- **CSV export** — export results from inside the TUI.
- **Compat mode** (`--compat`) — ASCII-only borders and 16-color ANSI styles
  for RMM consoles and restricted terminals.
- **Auto-start** — `--range` + `--scan` begins scanning without UI navigation.
- **Continuous ping / tracert overlays** — live output streamed inside the TUI.
- **Wake-on-LAN** — send magic packets to selected hosts.

[ratatui]: https://github.com/ratatui-org/ratatui

---

## Screenshot

<!-- TODO: Add a screenshot or GIF here -->

---

## Installation

### Download a pre-built binary (recommended)

1. Go to the [Releases] page.
2. Download `ipscannr-vX.Y.Z-x86_64-windows.zip`.
3. Extract `ipscannr.exe` to any directory on your `PATH`.

[Releases]: https://github.com/DailenG/ipscannr/releases

### Build from source

Requires Rust stable and the MSVC toolchain (`x86_64-pc-windows-msvc`).

```powershell
cargo build --release
# binary: target\release\ipscannr.exe
```

---

## Usage

```
ipscannr [OPTIONS]

Options:
  -r, --range <RANGE>   IP range to scan
      --scan            Start scanning immediately on launch
      --compat          ASCII-only rendering for RMM / limited consoles
  -h, --help            Print help
  -V, --version         Print version
```

### Range formats

| Format | Example |
|--------|---------|
| CIDR | `192.168.1.0/24` |
| Short range | `192.168.1.1-254` |
| Full range | `192.168.1.1-192.168.1.254` |
| Single IP | `192.168.1.1` |
| Comma-separated | `192.168.1.1,10.0.0.0/8` |

### Examples

```powershell
ipscannr                                          # interactive TUI
ipscannr --range 192.168.1.0/24 --scan           # auto-start scan
ipscannr --range 192.168.1.0/24 --scan --compat  # RMM console mode
```

### Key bindings

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Cycle focus between panes |
| `s` | Start scan |
| `x` | Stop scan |
| `Space` | Resume scan / toggle multi-select |
| `p` | Configure ports |
| `r` | Edit range |
| `f` | Toggle filter (all hosts / online only) |
| `e` | Export results (CSV or JSON) |
| `d` | Toggle details pane |
| `w` | Wake-on-LAN |
| `c` | Continuous ping overlay |
| `t` | Tracert overlay |
| `a` | Save host to list |
| `?` | Show help overlay |
| `↑` / `k`, `↓` / `j` | Navigate up/down |
| `PgUp` / `PgDn` | Page up/down |
| `q` / `Ctrl+C` | Quit |

---

## Cache

Results are persisted to `ipscannr_cache.json` in the working directory.
Override the path with the `IPSCANNR_CACHE_FILE` environment variable.

---

## License

MIT — see [LICENSE](LICENSE).
