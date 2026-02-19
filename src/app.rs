use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use ratatui::widgets::TableState;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::input::{Action, InputMode};
use crate::scanner::{
    get_active_adapters, get_mac_address, scan_hosts, AdapterInfo, DnsResolver, IpRange, MacInfo,
    PingResult, PortScanner, COMMON_PORTS,
};

/// Information about a scanned host
#[derive(Debug, Clone)]
pub struct HostInfo {
    pub ip: Ipv4Addr,
    pub is_alive: bool,
    pub rtt: Option<Duration>,
    pub hostname: Option<String>,
    pub mac: Option<MacInfo>,
    pub open_ports: Vec<u16>,
}

impl From<PingResult> for HostInfo {
    fn from(result: PingResult) -> Self {
        Self {
            ip: result.ip,
            is_alive: result.is_alive,
            rtt: result.rtt,
            hostname: None,
            mac: None,
            open_ports: Vec::new(),
        }
    }
}

/// Filter mode for displaying hosts
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FilterMode {
    All,
    OnlineOnly,
}

impl FilterMode {
    pub fn toggle(&self) -> Self {
        match self {
            FilterMode::All => FilterMode::OnlineOnly,
            FilterMode::OnlineOnly => FilterMode::All,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            FilterMode::All => "All",
            FilterMode::OnlineOnly => "Online",
        }
    }
}

/// Current scan state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanState {
    Idle,
    Scanning,
    Paused,
    Completed,
}

/// Focus state for panes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Focus {
    RangeInput,
    HostsTable,
    DetailsPane,
}

/// Application state
pub struct App {
    pub config: Config,
    pub input_mode: InputMode,
    pub scan_state: ScanState,
    pub focus: Focus,
    pub filter_mode: FilterMode,

    // Network adapters
    pub adapters: Vec<AdapterInfo>,
    pub adapter_index: Option<usize>, // None = custom input mode
    pub adapters_loading: bool,       // True while adapters are being loaded

    // Input fields
    pub range_input: String,
    pub range_cursor: usize,
    pub ports_input: String,
    pub ports_cursor: usize,

    // Scan results
    pub hosts: Vec<HostInfo>,
    pub filtered_hosts: Vec<usize>, // Indices into hosts
    pub table_state: TableState,

    // Multi-select (stored as IPs so sort doesn't invalidate)
    pub selected_hosts: HashSet<Ipv4Addr>,

    // Progress
    pub scan_total: usize,
    pub scan_completed: usize,

    // Communication
    scan_cancel_tx: Option<mpsc::Sender<()>>,
    scan_resume_tx: Option<mpsc::Sender<()>>,

    // DNS resolver
    dns_resolver: Arc<DnsResolver>,

    // Show details pane (can be toggled in full mode)
    pub show_details: bool,

    // Export / message state
    pub export_message: Option<String>,

    // Animation state for activity indicator
    pub animation_tick: u8,

    // Output overlay (continuous ping / tracert)
    pub overlay_title: String,
    pub overlay_lines: Vec<String>,
    pub overlay_scroll: usize,
    pub overlay_cancel_tx: Option<mpsc::Sender<()>>,
}

impl App {
    /// Create a new App with lazy adapter loading for fast startup
    pub fn new(config: Config) -> Self {
        // Start with default range - adapters will be loaded in background
        let range_input = config.default_range.clone();
        let range_cursor = range_input.len();

        Self {
            config,
            input_mode: InputMode::Normal,
            scan_state: ScanState::Idle,
            focus: Focus::RangeInput, // Default to Range pane
            filter_mode: FilterMode::All,

            adapters: Vec::new(),
            adapter_index: None,
            adapters_loading: true, // Will load in background

            range_input,
            range_cursor,
            ports_input: String::new(),
            ports_cursor: 0,

            hosts: Vec::new(),
            filtered_hosts: Vec::new(),
            table_state: TableState::default(),
            selected_hosts: HashSet::new(),

            scan_total: 0,
            scan_completed: 0,

            scan_cancel_tx: None,
            scan_resume_tx: None,
            dns_resolver: Arc::new(DnsResolver::default()),
            show_details: true,
            export_message: None,
            animation_tick: 0,

            overlay_title: String::new(),
            overlay_lines: Vec::new(),
            overlay_scroll: 0,
            overlay_cancel_tx: None,
        }
    }

    /// Load adapters (call from async context)
    pub fn load_adapters(&mut self) {
        self.adapters = get_active_adapters();
        self.adapters_loading = false;

        // Set default range from first adapter (preferring ethernet)
        if !self.adapters.is_empty() && self.adapter_index.is_none() {
            self.adapter_index = Some(0);
            self.range_input = self.adapters[0].subnet.clone();
            self.range_cursor = self.range_input.len();
        }
    }

    /// Tick the animation (call every frame)
    pub fn tick_animation(&mut self) {
        self.animation_tick = (self.animation_tick + 1) % 12; // Cycle through 0-11
    }

    /// Get the current adapter info if one is selected
    pub fn current_adapter(&self) -> Option<&AdapterInfo> {
        self.adapter_index.and_then(|i| self.adapters.get(i))
    }

    /// Cycle to next adapter (down arrow)
    pub fn next_adapter(&mut self) {
        if self.adapters.is_empty() {
            return;
        }

        match self.adapter_index {
            Some(i) => {
                if i + 1 < self.adapters.len() {
                    // Move to next adapter
                    self.adapter_index = Some(i + 1);
                    self.range_input = self.adapters[i + 1].subnet.clone();
                } else {
                    // Move to custom input (blank)
                    self.adapter_index = None;
                    self.range_input.clear();
                }
            }
            None => {
                // Cycle back to first adapter
                self.adapter_index = Some(0);
                self.range_input = self.adapters[0].subnet.clone();
            }
        }
        self.range_cursor = self.range_input.len();
    }

    /// Cycle to previous adapter (up arrow)
    pub fn prev_adapter(&mut self) {
        if self.adapters.is_empty() {
            return;
        }

        match self.adapter_index {
            Some(i) => {
                if i > 0 {
                    // Move to previous adapter
                    self.adapter_index = Some(i - 1);
                    self.range_input = self.adapters[i - 1].subnet.clone();
                } else {
                    // Move to custom input (blank)
                    self.adapter_index = None;
                    self.range_input.clear();
                }
            }
            None => {
                // Cycle to last adapter
                let last = self.adapters.len() - 1;
                self.adapter_index = Some(last);
                self.range_input = self.adapters[last].subnet.clone();
            }
        }
        self.range_cursor = self.range_input.len();
    }

    pub fn handle_action(&mut self, action: Action) -> Result<Option<AppCommand>> {
        // Global escape handler for pausing scan (not in overlay mode)
        if action == Action::Cancel
            && self.scan_state == ScanState::Scanning
            && self.input_mode != InputMode::OutputOverlay
        {
            self.pause_scan();
            return Ok(None);
        }

        // Spacebar resumes a paused scan (takes priority over host selection)
        if action == Action::ToggleSelect
            && self.scan_state == ScanState::Paused
            && self.input_mode == InputMode::Normal
        {
            return Ok(Some(AppCommand::ResumeScan));
        }

        match self.input_mode {
            InputMode::Normal => self.handle_normal_action(action),
            InputMode::EditingRange => self.handle_editing_range_action(action),
            InputMode::EditingPorts => self.handle_editing_ports_action(action),
            InputMode::Help => self.handle_help_action(action),
            InputMode::Exporting => self.handle_export_action(action),
            InputMode::OutputOverlay => self.handle_overlay_action(action),
        }
    }

    fn handle_normal_action(&mut self, action: Action) -> Result<Option<AppCommand>> {
        match action {
            Action::Quit => Ok(Some(AppCommand::Quit)),
            Action::Cancel => {
                // Escape in normal mode - if in range pane, go to hosts table
                if self.focus == Focus::RangeInput {
                    self.focus = Focus::HostsTable;
                }
                Ok(None)
            }
            Action::Backspace => {
                // Backspace in range pane → enter custom edit mode and delete last char
                if self.focus == Focus::RangeInput {
                    self.input_mode = InputMode::EditingRange;
                    self.adapter_index = None;
                    self.range_cursor = self.range_input.len();
                    if self.range_cursor > 0 {
                        self.range_cursor -= 1;
                        self.range_input.remove(self.range_cursor);
                    }
                }
                Ok(None)
            }
            Action::ToggleSelect => {
                // Toggle multi-selection for the currently highlighted host
                if self.focus == Focus::HostsTable {
                    if let Some(host) = self.selected_host() {
                        let ip = host.ip;
                        if self.selected_hosts.contains(&ip) {
                            self.selected_hosts.remove(&ip);
                        } else {
                            self.selected_hosts.insert(ip);
                        }
                    }
                }
                Ok(None)
            }
            Action::StartScan => {
                if self.scan_state != ScanState::Scanning {
                    return Ok(Some(AppCommand::StartScan));
                }
                Ok(None)
            }
            Action::StopScan => {
                if self.scan_state == ScanState::Scanning {
                    self.pause_scan();
                }
                Ok(None)
            }
            Action::EditRange => {
                self.focus = Focus::RangeInput;
                self.input_mode = InputMode::EditingRange;
                self.range_cursor = self.range_input.len();
                // When entering edit mode, switch to custom input
                self.adapter_index = None;
                Ok(None)
            }
            Action::ConfigurePorts => {
                if self.focus == Focus::DetailsPane {
                    // Scan ports for the currently selected host
                    return Ok(Some(AppCommand::ScanPortsForSelected));
                }
                self.input_mode = InputMode::EditingPorts;
                self.ports_cursor = self.ports_input.len();
                Ok(None)
            }
            Action::ToggleFilter => {
                self.filter_mode = self.filter_mode.toggle();
                self.update_filtered_hosts();
                Ok(None)
            }
            Action::Export => {
                self.input_mode = InputMode::Exporting;
                Ok(None)
            }
            Action::ToggleDetails => {
                self.show_details = !self.show_details;
                Ok(None)
            }
            Action::Help => {
                self.input_mode = InputMode::Help;
                Ok(None)
            }
            Action::WakeOnLan => {
                match self.send_wol() {
                    Ok(Some(msg)) => self.export_message = Some(msg),
                    Ok(None) => {
                        self.export_message =
                            Some("Select a host with a known MAC address for WOL".to_string())
                    }
                    Err(e) => self.export_message = Some(format!("WOL error: {}", e)),
                }
                Ok(None)
            }
            Action::ContinuousPing => {
                if let Some(host) = self.selected_host() {
                    let ip = host.ip;
                    return Ok(Some(AppCommand::StartContinuousPing(ip)));
                }
                Ok(None)
            }
            Action::RunTracert => {
                if let Some(host) = self.selected_host() {
                    let ip = host.ip;
                    return Ok(Some(AppCommand::StartTracert(ip)));
                }
                Ok(None)
            }
            Action::SaveHost => {
                self.save_selected_host()?;
                Ok(None)
            }
            Action::NavigateUp => {
                if self.focus == Focus::RangeInput {
                    self.prev_adapter();
                } else {
                    self.select_previous();
                }
                Ok(None)
            }
            Action::NavigateDown => {
                if self.focus == Focus::RangeInput {
                    self.next_adapter();
                } else {
                    self.select_next();
                }
                Ok(None)
            }
            Action::NavigatePageUp => {
                if self.focus != Focus::RangeInput {
                    for _ in 0..10 {
                        self.select_previous();
                    }
                }
                Ok(None)
            }
            Action::NavigatePageDown => {
                if self.focus != Focus::RangeInput {
                    for _ in 0..10 {
                        self.select_next();
                    }
                }
                Ok(None)
            }
            Action::NavigateHome => {
                if self.focus != Focus::RangeInput && !self.filtered_hosts.is_empty() {
                    self.table_state.select(Some(0));
                }
                Ok(None)
            }
            Action::NavigateEnd => {
                if self.focus != Focus::RangeInput && !self.filtered_hosts.is_empty() {
                    self.table_state.select(Some(self.filtered_hosts.len() - 1));
                }
                Ok(None)
            }
            Action::Select => {
                // Enter key
                if self.focus == Focus::RangeInput {
                    // Start scan when pressing Enter on Range pane
                    if self.scan_state != ScanState::Scanning {
                        return Ok(Some(AppCommand::StartScan));
                    }
                }
                Ok(None)
            }
            Action::SwitchPane => {
                self.focus = match self.focus {
                    Focus::RangeInput => Focus::HostsTable,
                    Focus::HostsTable => {
                        if self.show_details {
                            Focus::DetailsPane
                        } else {
                            Focus::RangeInput
                        }
                    }
                    Focus::DetailsPane => Focus::RangeInput,
                };
                Ok(None)
            }
            Action::Character(c) => {
                // Typing while the range pane is focused auto-enters edit mode
                if self.focus == Focus::RangeInput {
                    self.input_mode = InputMode::EditingRange;
                    self.adapter_index = None;
                    self.range_cursor = self.range_input.len();
                    self.range_input.insert(self.range_cursor, c);
                    self.range_cursor += 1;
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn handle_editing_range_action(&mut self, action: Action) -> Result<Option<AppCommand>> {
        match action {
            Action::Cancel => {
                self.input_mode = InputMode::Normal;
            }
            Action::Select => {
                // Enter - exit editing and start scan
                self.input_mode = InputMode::Normal;
                if self.scan_state != ScanState::Scanning && !self.range_input.is_empty() {
                    return Ok(Some(AppCommand::StartScan));
                }
            }
            Action::Backspace => {
                if self.range_cursor > 0 {
                    self.range_cursor -= 1;
                    self.range_input.remove(self.range_cursor);
                    // Switch to custom mode when editing
                    self.adapter_index = None;
                }
            }
            Action::Delete => {
                if self.range_cursor < self.range_input.len() {
                    self.range_input.remove(self.range_cursor);
                    self.adapter_index = None;
                }
            }
            Action::NavigateUp => {
                // Left arrow in edit mode
                if self.range_cursor > 0 {
                    self.range_cursor -= 1;
                }
            }
            Action::NavigateDown => {
                // Right arrow in edit mode
                if self.range_cursor < self.range_input.len() {
                    self.range_cursor += 1;
                }
            }
            Action::NavigateHome => {
                self.range_cursor = 0;
            }
            Action::NavigateEnd => {
                self.range_cursor = self.range_input.len();
            }
            Action::Character(c) => {
                self.range_input.insert(self.range_cursor, c);
                self.range_cursor += 1;
                // Switch to custom mode when typing
                self.adapter_index = None;
            }
            _ => {}
        }
        Ok(None)
    }

    fn handle_editing_ports_action(&mut self, action: Action) -> Result<Option<AppCommand>> {
        match action {
            Action::Cancel => {
                self.input_mode = InputMode::Normal;
            }
            Action::Select => {
                self.input_mode = InputMode::Normal;
            }
            Action::Backspace => {
                if self.ports_cursor > 0 {
                    self.ports_cursor -= 1;
                    self.ports_input.remove(self.ports_cursor);
                }
            }
            Action::Delete => {
                if self.ports_cursor < self.ports_input.len() {
                    self.ports_input.remove(self.ports_cursor);
                }
            }
            Action::NavigateUp => {
                if self.ports_cursor > 0 {
                    self.ports_cursor -= 1;
                }
            }
            Action::NavigateDown => {
                if self.ports_cursor < self.ports_input.len() {
                    self.ports_cursor += 1;
                }
            }
            Action::NavigateHome => {
                self.ports_cursor = 0;
            }
            Action::NavigateEnd => {
                self.ports_cursor = self.ports_input.len();
            }
            Action::Character(c) => {
                self.ports_input.insert(self.ports_cursor, c);
                self.ports_cursor += 1;
            }
            _ => {}
        }
        Ok(None)
    }

    fn handle_help_action(&mut self, action: Action) -> Result<Option<AppCommand>> {
        if action == Action::Cancel {
            self.input_mode = InputMode::Normal;
        }
        Ok(None)
    }

    fn handle_export_action(&mut self, action: Action) -> Result<Option<AppCommand>> {
        match action {
            Action::Cancel => {
                self.input_mode = InputMode::Normal;
            }
            Action::Character('c') => {
                self.export_csv()?;
                self.input_mode = InputMode::Normal;
            }
            Action::Character('j') => {
                self.export_json()?;
                self.input_mode = InputMode::Normal;
            }
            _ => {}
        }
        Ok(None)
    }

    fn handle_overlay_action(&mut self, action: Action) -> Result<Option<AppCommand>> {
        match action {
            Action::StopOverlay => {
                if let Some(tx) = &self.overlay_cancel_tx {
                    let _ = tx.try_send(());
                }
                self.overlay_cancel_tx = None;
                self.input_mode = InputMode::Normal;
                self.overlay_lines.clear();
                self.overlay_scroll = 0;
            }
            Action::NavigateUp => {
                self.overlay_scroll = self.overlay_scroll.saturating_sub(1);
            }
            Action::NavigateDown => {
                self.overlay_scroll += 1; // clamped during render
            }
            Action::NavigateHome => {
                self.overlay_scroll = 0;
            }
            Action::NavigateEnd => {
                self.overlay_scroll = self.overlay_lines.len().saturating_sub(1);
            }
            _ => {}
        }
        Ok(None)
    }

    fn pause_scan(&mut self) {
        if self.scan_state == ScanState::Scanning {
            if let Some(tx) = &self.scan_cancel_tx {
                let _ = tx.try_send(());
            }
            self.scan_state = ScanState::Paused;
        }
    }

    pub fn resume_scan(&mut self) {
        if self.scan_state == ScanState::Paused {
            self.scan_state = ScanState::Scanning;
            if let Some(tx) = &self.scan_resume_tx {
                let _ = tx.try_send(());
            }
        }
    }

    fn select_next(&mut self) {
        if self.filtered_hosts.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.filtered_hosts.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn select_previous(&mut self) {
        if self.filtered_hosts.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.filtered_hosts.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    pub fn update_filtered_hosts(&mut self) {
        self.filtered_hosts = self
            .hosts
            .iter()
            .enumerate()
            .filter(|(_, h)| match self.filter_mode {
                FilterMode::All => true,
                FilterMode::OnlineOnly => h.is_alive,
            })
            .map(|(i, _)| i)
            .collect();

        // Adjust selection if needed
        if let Some(selected) = self.table_state.selected() {
            if selected >= self.filtered_hosts.len() {
                if self.filtered_hosts.is_empty() {
                    self.table_state.select(None);
                } else {
                    self.table_state.select(Some(self.filtered_hosts.len() - 1));
                }
            }
        }
    }

    pub fn get_filtered_hosts(&self) -> Vec<&HostInfo> {
        self.filtered_hosts
            .iter()
            .map(|&i| &self.hosts[i])
            .collect()
    }

    pub fn selected_host(&self) -> Option<&HostInfo> {
        self.table_state
            .selected()
            .and_then(|i| self.filtered_hosts.get(i))
            .map(|&i| &self.hosts[i])
    }

    pub fn selected_host_mut(&mut self) -> Option<&mut HostInfo> {
        let idx = self
            .table_state
            .selected()
            .and_then(|i| self.filtered_hosts.get(i).copied())?;
        self.hosts.get_mut(idx)
    }

    pub fn progress(&self) -> f64 {
        if self.scan_total == 0 {
            0.0
        } else {
            self.scan_completed as f64 / self.scan_total as f64
        }
    }

    /// Dots12-style CLI spinner frames (braille characters)
    const SPINNER_FRAMES: &'static [&'static str] = &[
        "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
    ];

    /// Get current spinner frame based on animation tick
    fn spinner(&self) -> &'static str {
        Self::SPINNER_FRAMES[(self.animation_tick as usize) % Self::SPINNER_FRAMES.len()]
    }

    /// Short state string for the bottom status bar (must stay compact)
    pub fn status_text(&self) -> String {
        if self.adapters_loading {
            return format!("{} Loading", self.spinner());
        }

        match self.scan_state {
            ScanState::Idle => "Ready".to_string(),
            ScanState::Scanning => {
                format!("{} {}/{}", self.spinner(), self.scan_completed, self.scan_total)
            }
            ScanState::Paused => "Paused".to_string(),
            ScanState::Completed => "Done".to_string(),
        }
    }

    /// Full summary shown in the header Status box after a scan completes
    pub fn completion_summary(&self) -> String {
        let online = self.hosts.iter().filter(|h| h.is_alive).count();
        format!("{} hosts ({} online)", self.hosts.len(), online)
    }

    pub async fn start_scan(&mut self) -> Result<mpsc::Receiver<ScanEvent>> {
        let range = IpRange::parse(&self.range_input)?;
        let addresses: Vec<Ipv4Addr> = range.addresses().to_vec();

        self.hosts.clear();
        self.filtered_hosts.clear();
        self.selected_hosts.clear();
        self.table_state.select(None);
        self.scan_total = addresses.len();
        self.scan_completed = 0;
        self.scan_state = ScanState::Scanning;
        // Move focus to hosts table when scan starts
        self.focus = Focus::HostsTable;

        let (event_tx, event_rx) = mpsc::channel(256);
        let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);
        self.scan_cancel_tx = Some(cancel_tx);

        let config = self.config.clone();
        let dns_resolver = Arc::clone(&self.dns_resolver);

        tokio::spawn(async move {
            let (ping_tx, mut ping_rx) = mpsc::channel(256);

            // Start ping scan
            let addresses_clone = addresses.clone();
            let ping_config = config.ping.clone();
            tokio::spawn(async move {
                let _ = scan_hosts(addresses_clone, ping_config, ping_tx).await;
            });

            // Process results
            loop {
                tokio::select! {
                    _ = cancel_rx.recv() => {
                        break;
                    }
                    result = ping_rx.recv() => {
                        match result {
                            Some(ping_result) => {
                                let mut host: HostInfo = ping_result.into();

                                // Resolve hostname for alive hosts
                                if host.is_alive && config.resolve_hostnames {
                                    if let Some(hostname) = dns_resolver.resolve(host.ip).await {
                                        host.hostname = Some(hostname);
                                    }
                                }

                                // Get MAC address for alive hosts on local network
                                if host.is_alive && config.detect_mac {
                                    if let Some(mac) = get_mac_address(host.ip) {
                                        host.mac = Some(mac);
                                    }
                                }

                                let _ = event_tx.send(ScanEvent::HostDiscovered(host)).await;
                            }
                            None => {
                                let _ = event_tx.send(ScanEvent::ScanComplete).await;
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(event_rx)
    }

    pub fn handle_scan_event(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::HostDiscovered(host) => {
                self.hosts.push(host);
                self.scan_completed += 1;
                self.update_filtered_hosts();

                // Auto-select first host
                if self.table_state.selected().is_none() && !self.filtered_hosts.is_empty() {
                    self.table_state.select(Some(0));
                }
            }
            ScanEvent::ScanComplete => {
                if self.scan_state != ScanState::Paused {
                    self.scan_state = ScanState::Completed;
                }
                self.scan_cancel_tx = None;

                // Sort hosts by IP
                self.hosts.sort_by_key(|h| h.ip);
                self.update_filtered_hosts();
            }
        }
    }

    pub async fn scan_ports_for_selected(&mut self) -> Result<()> {
        let Some(host) = self.selected_host() else {
            return Ok(());
        };

        if !host.is_alive {
            return Ok(());
        }

        let ip = host.ip;
        let scanner = PortScanner::new(self.config.port_scan.clone());
        let results = scanner.scan_ports(ip, COMMON_PORTS).await;

        if let Some(host) = self.selected_host_mut() {
            host.open_ports = results
                .into_iter()
                .filter(|r| r.is_open)
                .map(|r| r.port)
                .collect();
        }

        Ok(())
    }

    /// Send a Wake-on-LAN magic packet to the selected host's MAC address
    pub fn send_wol(&self) -> Result<Option<String>> {
        let Some(host) = self.selected_host() else {
            return Ok(None);
        };
        let Some(mac) = &host.mac else {
            return Ok(Some(format!(
                "No MAC address for {} — WOL unavailable",
                host.ip
            )));
        };

        // Parse MAC bytes (supports XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
        let parts: Vec<u8> = mac
            .address
            .split(|c| c == ':' || c == '-')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if parts.len() != 6 {
            return Ok(Some(format!("Invalid MAC address: {}", mac.address)));
        }

        // Build magic packet: 6×0xFF then MAC repeated 16 times
        let mut packet = vec![0xFF_u8; 6];
        for _ in 0..16 {
            packet.extend_from_slice(&parts);
        }

        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.set_broadcast(true)?;
        socket.send_to(&packet, "255.255.255.255:9")?;

        Ok(Some(format!("WOL packet sent to {} ({})", host.ip, mac.address)))
    }

    /// Save the selected host's details to a text file
    pub fn save_selected_host(&mut self) -> Result<()> {
        let Some(host) = self.selected_host() else {
            self.export_message = Some("No host selected".to_string());
            return Ok(());
        };

        let filename = format!("ipscannr_host_{}.txt", host.ip);
        let mut content = String::new();
        content.push_str(&format!("IP:     {}\n", host.ip));
        content.push_str(&format!(
            "Status: {}\n",
            if host.is_alive { "Online" } else { "Offline" }
        ));
        if let Some(rtt) = host.rtt {
            content.push_str(&format!("RTT:    {}ms\n", rtt.as_millis()));
        }
        if let Some(hostname) = &host.hostname {
            content.push_str(&format!("Host:   {}\n", hostname));
        }
        if let Some(mac) = &host.mac {
            content.push_str(&format!("MAC:    {}\n", mac.address));
            if let Some(vendor) = &mac.vendor {
                content.push_str(&format!("Vendor: {}\n", vendor));
            }
        }
        if !host.open_ports.is_empty() {
            content.push_str("\nOpen Ports:\n");
            for port in &host.open_ports {
                content.push_str(&format!("  {}\n", port));
            }
        }

        std::fs::write(&filename, content)?;
        self.export_message = Some(format!("Saved to {}", filename));
        Ok(())
    }

    /// Get hosts to include in export (selected subset, or all if nothing selected)
    fn hosts_for_export(&self) -> Vec<&HostInfo> {
        if self.selected_hosts.is_empty() {
            self.hosts.iter().collect()
        } else {
            self.hosts
                .iter()
                .filter(|h| self.selected_hosts.contains(&h.ip))
                .collect()
        }
    }

    fn export_csv(&mut self) -> Result<()> {
        let filename = format!("ipscannr_export_{}.csv", chrono_timestamp());
        let mut wtr = csv::Writer::from_path(&filename)?;

        wtr.write_record(["IP", "Status", "RTT (ms)", "Hostname", "MAC", "Vendor", "Ports"])?;

        for host in self.hosts_for_export() {
            wtr.write_record([
                host.ip.to_string(),
                if host.is_alive { "Online" } else { "Offline" }.to_string(),
                host.rtt.map(|d| d.as_millis().to_string()).unwrap_or_default(),
                host.hostname.clone().unwrap_or_default(),
                host.mac.as_ref().map(|m| m.address.clone()).unwrap_or_default(),
                host.mac.as_ref().and_then(|m| m.vendor.clone()).unwrap_or_default(),
                host.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(";"),
            ])?;
        }

        wtr.flush()?;
        self.export_message = Some(format!("Exported to {}", filename));
        Ok(())
    }

    fn export_json(&mut self) -> Result<()> {
        let filename = format!("ipscannr_export_{}.json", chrono_timestamp());

        #[derive(serde::Serialize)]
        struct ExportHost {
            ip: String,
            is_alive: bool,
            rtt_ms: Option<u128>,
            hostname: Option<String>,
            mac_address: Option<String>,
            mac_vendor: Option<String>,
            open_ports: Vec<u16>,
        }

        let export_data: Vec<ExportHost> = self
            .hosts_for_export()
            .into_iter()
            .map(|h| ExportHost {
                ip: h.ip.to_string(),
                is_alive: h.is_alive,
                rtt_ms: h.rtt.map(|d| d.as_millis()),
                hostname: h.hostname.clone(),
                mac_address: h.mac.as_ref().map(|m| m.address.clone()),
                mac_vendor: h.mac.as_ref().and_then(|m| m.vendor.clone()),
                open_ports: h.open_ports.clone(),
            })
            .collect();

        let json = serde_json::to_string_pretty(&export_data)?;
        std::fs::write(&filename, json)?;

        self.export_message = Some(format!("Exported to {}", filename));
        Ok(())
    }
}

/// Commands returned by the app
#[derive(Debug)]
pub enum AppCommand {
    Quit,
    StartScan,
    ResumeScan,
    ScanPortsForSelected,
    StartContinuousPing(Ipv4Addr),
    StartTracert(Ipv4Addr),
}

/// Events from the scan process
#[derive(Debug)]
pub enum ScanEvent {
    HostDiscovered(HostInfo),
    ScanComplete,
}

fn chrono_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}
