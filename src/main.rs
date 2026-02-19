mod app;
mod config;
mod input;
mod scanner;
mod ui;

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame, Terminal,
};
use tokio::sync::mpsc;

use app::{App, AppCommand, Focus, ScanEvent};
use config::Config;
use input::{handle_key, InputMode};
use ui::{AppLayout, DetailsPane, InputBar, ProgressBar, ScanTable, StatusBar, Theme};

#[derive(Parser)]
#[command(name = "ipscannr")]
#[command(about = "A terminal-based IP scanner - hack the planet!")]
#[command(version)]
struct Cli {
    /// IP range to scan (e.g., 192.168.1.0/24)
    #[arg(short, long)]
    range: Option<String>,

    /// Start scanning immediately
    #[arg(short, long)]
    scan: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut config = Config::default();
    if let Some(range) = cli.range {
        config.default_range = range;
    }
    let mut app = App::new(config);

    // Run app
    let result = run_app(&mut terminal, &mut app, cli.scan).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }

    Ok(())
}

async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    auto_scan: bool,
) -> Result<()> {
    let mut scan_rx: Option<mpsc::Receiver<ScanEvent>> = None;
    let mut overlay_rx: Option<mpsc::Receiver<String>> = None;

    // Load adapters in background for faster startup
    let (adapter_tx, mut adapter_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        use crate::scanner::get_active_adapters;
        let adapters = get_active_adapters();
        let _ = adapter_tx.send(adapters).await;
    });

    // Auto-start scan if requested (will wait for adapters)
    let mut pending_auto_scan = auto_scan;

    loop {
        // Tick animation for activity indicator
        app.tick_animation();

        terminal.draw(|f| draw_ui(f, app))?;

        // Handle events with timeout for scan updates
        let timeout = Duration::from_millis(50);

        tokio::select! {
            // Check for adapter loading completion
            adapters = adapter_rx.recv(), if app.adapters_loading => {
                if let Some(adapters) = adapters {
                    app.adapters = adapters;
                    app.adapters_loading = false;
                    // Set default range from first adapter
                    if !app.adapters.is_empty() && app.adapter_index.is_none() {
                        app.adapter_index = Some(0);
                        app.range_input = app.adapters[0].subnet.clone();
                        app.range_cursor = app.range_input.len();
                    }
                    // Start auto-scan if requested
                    if pending_auto_scan {
                        pending_auto_scan = false;
                        match app.start_scan().await {
                            Ok(rx) => scan_rx = Some(rx),
                            Err(e) => app.export_message = Some(format!("Error: {}", e)),
                        }
                    }
                }
            }

            // Check for scan events
            event = async {
                if let Some(rx) = &mut scan_rx {
                    rx.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                if let Some(scan_event) = event {
                    app.handle_scan_event(scan_event);
                } else {
                    scan_rx = None;
                }
            }

            // Check for overlay output (continuous ping / tracert)
            line = async {
                if let Some(rx) = &mut overlay_rx {
                    rx.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                match line {
                    Some(text) => {
                        // Auto-scroll when near bottom
                        let at_bottom = app.overlay_lines.is_empty()
                            || app.overlay_scroll + 1 >= app.overlay_lines.len();
                        app.overlay_lines.push(text);
                        if at_bottom {
                            app.overlay_scroll = app.overlay_lines.len().saturating_sub(1);
                        }
                    }
                    None => {
                        // Task finished — keep overlay open for reading, title updated
                        overlay_rx = None;
                        if app.input_mode == InputMode::OutputOverlay {
                            let done_title = format!("{} [Done — Esc to close]", app.overlay_title);
                            app.overlay_title = done_title;
                        }
                    }
                }
            }

            // Check for user input
            _ = tokio::time::sleep(timeout) => {
                if event::poll(Duration::from_millis(0))? {
                    if let Event::Key(key) = event::read()? {
                        // Only handle key press events (not release)
                        if key.kind == KeyEventKind::Press {
                            // Any keypress dismisses a notification message
                            app.export_message = None;

                            let action = handle_key(key, app.input_mode);
                            match app.handle_action(action)? {
                                Some(AppCommand::Quit) => return Ok(()),
                                Some(AppCommand::StartScan) => {
                                    match app.start_scan().await {
                                        Ok(rx) => scan_rx = Some(rx),
                                        Err(e) => app.export_message = Some(format!("Error: {}", e)),
                                    }
                                }
                                Some(AppCommand::ResumeScan) => {
                                    // Resume just restarts the scan from the beginning
                                    app.resume_scan();
                                    match app.start_scan().await {
                                        Ok(rx) => scan_rx = Some(rx),
                                        Err(e) => app.export_message = Some(format!("Error: {}", e)),
                                    }
                                }
                                Some(AppCommand::ScanPortsForSelected) => {
                                    if let Err(e) = app.scan_ports_for_selected().await {
                                        app.export_message = Some(format!("Port scan error: {}", e));
                                    }
                                }
                                Some(AppCommand::StartContinuousPing(ip)) => {
                                    overlay_rx = Some(start_continuous_ping(ip, app));
                                }
                                Some(AppCommand::StartTracert(ip)) => {
                                    overlay_rx = Some(start_tracert(ip, app));
                                }
                                None => {}
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Spawn a continuous ping task and return the output channel receiver
fn start_continuous_ping(ip: Ipv4Addr, app: &mut App) -> mpsc::Receiver<String> {
    app.overlay_title = format!("Continuous Ping — {}", ip);
    app.overlay_lines.clear();
    app.overlay_scroll = 0;
    app.input_mode = InputMode::OutputOverlay;

    let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);
    app.overlay_cancel_tx = Some(cancel_tx);

    let (line_tx, line_rx) = mpsc::channel::<String>(256);

    tokio::spawn(async move {
        let mut seq = 0u32;
        loop {
            seq += 1;
            // Wait 1 second or cancel
            let cancelled = tokio::select! {
                _ = cancel_rx.recv() => true,
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => false,
            };
            if cancelled {
                break;
            }

            let start = std::time::Instant::now();
            let mut alive = false;

            // TCP-based ping across common ports (mirrors scanner behaviour)
            for &port in &[80u16, 443, 22, 445, 139] {
                let addr =
                    std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port);
                let result = tokio::time::timeout(
                    tokio::time::Duration::from_millis(1000),
                    tokio::net::TcpStream::connect(addr),
                )
                .await;
                match result {
                    Ok(Ok(_)) => {
                        alive = true;
                        break;
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                        alive = true;
                        break;
                    }
                    _ => {}
                }
            }

            let rtt = start.elapsed();
            let line = if alive {
                format!("[{}] Reply from {}: time={}ms", seq, ip, rtt.as_millis())
            } else {
                format!("[{}] Request timed out for {}", seq, ip)
            };

            if line_tx.send(line).await.is_err() {
                break;
            }
        }
    });

    line_rx
}

/// Spawn a tracert process and return the output channel receiver
fn start_tracert(ip: Ipv4Addr, app: &mut App) -> mpsc::Receiver<String> {
    app.overlay_title = format!("Tracert — {}", ip);
    app.overlay_lines.clear();
    app.overlay_scroll = 0;
    app.input_mode = InputMode::OutputOverlay;

    let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);
    app.overlay_cancel_tx = Some(cancel_tx);

    let (line_tx, line_rx) = mpsc::channel::<String>(256);
    let ip_str = ip.to_string();

    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::process::Command;

        let mut child = match Command::new("tracert")
            .arg(&ip_str)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                let _ = line_tx.send(format!("Failed to start tracert: {}", e)).await;
                return;
            }
        };

        let stdout = child.stdout.take().expect("stdout piped");
        let mut reader = BufReader::new(stdout).lines();

        loop {
            tokio::select! {
                _ = cancel_rx.recv() => {
                    let _ = child.kill().await;
                    break;
                }
                line = reader.next_line() => {
                    match line {
                        Ok(Some(l)) => {
                            if line_tx.send(l).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            }
        }
    });

    line_rx
}

fn draw_ui(f: &mut Frame, app: &App) {
    let size = f.area();
    let layout = AppLayout::new(size);

    // Clear with background color
    let bg_block = Block::default().style(Theme::default());
    f.render_widget(bg_block, size);

    // Draw header (input bar)
    draw_header(f, app, layout.header);

    // Build selected IPs set for the table
    let selected_ips = app.selected_hosts.clone();

    // Draw hosts table
    let filtered_hosts: Vec<_> = app.get_filtered_hosts().iter().map(|h| (*h).clone()).collect();
    let mut table_state = app.table_state.clone();
    let table = ScanTable::new(&filtered_hosts)
        .show_rtt(!layout.is_compact())
        .focused(app.focus == Focus::HostsTable)
        .selected_ips(&selected_ips);

    f.render_stateful_widget(table, layout.hosts_table, &mut table_state);

    // Draw details pane (full mode only)
    if let Some(details_area) = layout.details_pane {
        if app.show_details {
            let details = DetailsPane::new(app.selected_host())
                .focused(app.focus == Focus::DetailsPane);
            f.render_widget(details, details_area);
        }
    }

    // Draw status bar
    draw_status_bar(f, app, layout.status_bar, layout.is_compact());

    // Draw overlays
    match app.input_mode {
        InputMode::Help => draw_help_overlay(f, size),
        InputMode::Exporting => draw_export_overlay(f, app, size),
        InputMode::OutputOverlay => draw_output_overlay(f, app, size),
        _ => {}
    }

    // Draw export/notification message if present
    if let Some(msg) = &app.export_message {
        draw_message(f, size, msg);
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::horizontal([
        Constraint::Min(30),
        Constraint::Length(35), // Increased for longer status text
    ])
    .split(area);

    // Build range title with adapter info
    let range_title = if let Some(adapter) = app.current_adapter() {
        format!(" Range [{}] ", adapter.adapter_type)
    } else if app.adapter_index.is_none() && !app.adapters.is_empty() {
        " Range [Custom] ".to_string()
    } else {
        " Range ".to_string()
    };

    // Range input - focused if in RangeInput focus or editing
    let range_focused = app.focus == Focus::RangeInput || app.input_mode == InputMode::EditingRange;
    let range_bar = InputBar::new(&range_title, &app.range_input)
        .cursor_position(app.range_cursor)
        .focused(range_focused);
    f.render_widget(range_bar, chunks[0]);

    // Progress / Status
    let progress_area = chunks[1];
    let progress_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Theme::border())
        .title(" Status ")
        .title_style(Theme::title());

    let inner = progress_block.inner(progress_area);
    f.render_widget(progress_block, progress_area);

    if app.scan_state == app::ScanState::Scanning || app.scan_state == app::ScanState::Paused {
        let progress = ProgressBar::new(app.progress())
            .show_percentage(true);
        f.render_widget(progress, inner);
    } else {
        let status = Paragraph::new(app.status_text())
            .style(Theme::default());
        f.render_widget(status, inner);
    }
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect, compact: bool) {
    let filter_label = format!("Filter:{}", app.filter_mode.label());

    // Context-aware hotkeys based on focused pane
    let hotkeys: Vec<(&str, &str)> = if app.focus == Focus::DetailsPane {
        vec![
            ("W", "WOL"),
            ("P", "Ports"),
            ("C", "Ping"),
            ("T", "Tracert"),
            ("A", "Save"),
            ("Tab", "Switch"),
            ("Q", "Quit"),
        ]
    } else if compact {
        vec![
            ("S", "Scan"),
            ("R", "Range"),
            ("F", filter_label.as_str()),
            ("?", "Help"),
            ("Q", "Quit"),
        ]
    } else {
        vec![
            ("S", "Scan"),
            ("R", "Range"),
            ("P", "Ports"),
            ("F", filter_label.as_str()),
            ("E", "Export"),
            ("D", "Details"),
            ("?", "Help"),
            ("Q", "Quit"),
        ]
    };

    // Show multi-select count when any hosts are selected
    let selection_prefix = if !app.selected_hosts.is_empty() {
        format!("[{}✓] ", app.selected_hosts.len())
    } else {
        String::new()
    };

    let online_count = app.hosts.iter().filter(|h| h.is_alive).count();
    let status_right = format!(
        "{}{} hosts | {} online | {}",
        selection_prefix,
        app.hosts.len(),
        online_count,
        app.status_text()
    );

    let status_bar = StatusBar::new()
        .hotkeys(hotkeys)
        .status_right(status_right);

    f.render_widget(status_bar, area);
}

fn draw_help_overlay(f: &mut Frame, size: Rect) {
    let area = centered_rect(62, 85, size);

    f.render_widget(Clear, area);

    let help_text = vec![
        Line::from(Span::styled("IPSCANNR — Keyboard Shortcuts", Theme::title())),
        Line::from(""),
        Line::from(Span::styled("── Scanning ──────────────────────", Theme::dimmed())),
        Line::from(vec![
            Span::styled("[S]", Theme::hotkey()),
            Span::raw(" Start scan  "),
            Span::styled("[X]", Theme::hotkey()),
            Span::raw(" Stop/pause  "),
            Span::styled("[Space]", Theme::hotkey()),
            Span::raw(" Resume"),
        ]),
        Line::from(vec![
            Span::styled("[R]", Theme::hotkey()),
            Span::raw(" Edit IP range  "),
            Span::styled("[P]", Theme::hotkey()),
            Span::raw(" Configure ports"),
        ]),
        Line::from(vec![
            Span::styled("[F]", Theme::hotkey()),
            Span::raw(" Toggle filter (All / Online)"),
        ]),
        Line::from(""),
        Line::from(Span::styled("── Navigation ────────────────────", Theme::dimmed())),
        Line::from(vec![
            Span::styled("[↑/↓] or [j/k]", Theme::hotkey()),
            Span::raw(" Navigate rows"),
        ]),
        Line::from(vec![
            Span::styled("[PgUp/PgDn]", Theme::hotkey()),
            Span::raw(" Jump 10 rows  "),
            Span::styled("[Home/End]", Theme::hotkey()),
            Span::raw(" First/last"),
        ]),
        Line::from(vec![
            Span::styled("[Tab]", Theme::hotkey()),
            Span::raw(" Switch panes"),
        ]),
        Line::from(""),
        Line::from(Span::styled("── Selection & Export ────────────", Theme::dimmed())),
        Line::from(vec![
            Span::styled("[Space]", Theme::hotkey()),
            Span::raw(" Toggle host selection (multi-select)"),
        ]),
        Line::from(vec![
            Span::styled("[E]", Theme::hotkey()),
            Span::raw(" Export — all hosts, or selected subset"),
        ]),
        Line::from(""),
        Line::from(Span::styled("── Host Details (Details pane) ───", Theme::dimmed())),
        Line::from(vec![
            Span::styled("[W]", Theme::hotkey()),
            Span::raw(" Wake-on-LAN  "),
            Span::styled("[P]", Theme::hotkey()),
            Span::raw(" Scan ports"),
        ]),
        Line::from(vec![
            Span::styled("[C]", Theme::hotkey()),
            Span::raw(" Continuous ping  "),
            Span::styled("[T]", Theme::hotkey()),
            Span::raw(" Tracert"),
        ]),
        Line::from(vec![
            Span::styled("[A]", Theme::hotkey()),
            Span::raw(" Save host to file  "),
            Span::styled("[D]", Theme::hotkey()),
            Span::raw(" Toggle details pane"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("[Q] or [Ctrl+C]", Theme::hotkey()),
            Span::raw(" Quit"),
        ]),
        Line::from(""),
        Line::from(Span::styled("Press any key to close", Theme::dimmed())),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Theme::border_focused())
                .title(" Help ")
                .title_style(Theme::title()),
        )
        .style(Theme::default())
        .wrap(Wrap { trim: false });

    f.render_widget(help, area);
}

fn draw_export_overlay(f: &mut Frame, app: &App, size: Rect) {
    let area = centered_rect(42, 28, size);

    f.render_widget(Clear, area);

    let scope = if app.selected_hosts.is_empty() {
        format!("All {} hosts", app.hosts.len())
    } else {
        format!("{} selected host(s)", app.selected_hosts.len())
    };

    let text = vec![
        Line::from(Span::styled("Export Results", Theme::title())),
        Line::from(""),
        Line::from(vec![
            Span::styled("Scope: ", Theme::dimmed()),
            Span::styled(scope, Theme::default()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("[C]", Theme::hotkey()),
            Span::raw(" Export as CSV"),
        ]),
        Line::from(vec![
            Span::styled("[J]", Theme::hotkey()),
            Span::raw(" Export as JSON"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("[Esc]", Theme::hotkey()),
            Span::raw(" Cancel"),
        ]),
    ];

    let export = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Theme::border_focused())
                .title(" Export ")
                .title_style(Theme::title()),
        )
        .style(Theme::default());

    f.render_widget(export, area);
}

fn draw_output_overlay(f: &mut Frame, app: &App, size: Rect) {
    let area = centered_rect(72, 80, size);
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Theme::border_focused())
        .title(format!(" {} ", app.overlay_title))
        .title_style(Theme::title());

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    // Reserve last line for hint bar
    let content_height = (inner.height as usize).saturating_sub(1);
    let max_scroll = app.overlay_lines.len().saturating_sub(content_height);
    let scroll = app.overlay_scroll.min(max_scroll);

    let content_lines: Vec<Line> = app
        .overlay_lines
        .iter()
        .skip(scroll)
        .take(content_height)
        .map(|l| Line::from(l.as_str()))
        .collect();

    let content_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: (content_height as u16).min(inner.height),
    };
    let hint_area = Rect {
        x: inner.x,
        y: inner.y + content_area.height,
        width: inner.width,
        height: 1,
    };

    let content = Paragraph::new(content_lines).style(Theme::default());
    f.render_widget(content, content_area);

    let hint = Paragraph::new(Line::from(Span::styled(
        "[Esc/Q] Stop   [↑↓/j/k] Scroll   [Home/End] Top/Bottom",
        Theme::dimmed(),
    )));
    f.render_widget(hint, hint_area);
}

fn draw_message(f: &mut Frame, size: Rect, message: &str) {
    let area = centered_rect(50, 10, size);

    f.render_widget(Clear, area);

    let msg = Paragraph::new(message)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Theme::border_focused())
                .title(" Message ")
                .title_style(Theme::title()),
        )
        .style(Theme::default())
        .wrap(Wrap { trim: true });

    f.render_widget(msg, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(r);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(popup_layout[1])[1]
}
