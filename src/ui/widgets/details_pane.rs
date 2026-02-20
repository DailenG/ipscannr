use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};

use crate::app::HostInfo;
use crate::cache::format_cache_age;
use crate::scanner::get_service_name;
use crate::ui::theme::{Compat, Theme};

pub struct DetailsPane<'a> {
    host: Option<&'a HostInfo>,
    focused: bool,
    port_scanning: bool,
    compat: bool,
}

impl<'a> DetailsPane<'a> {
    pub fn new(host: Option<&'a HostInfo>) -> Self {
        Self {
            host,
            focused: false,
            port_scanning: false,
            compat: false,
        }
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn port_scanning(mut self, scanning: bool) -> Self {
        self.port_scanning = scanning;
        self
    }

    pub fn compat(mut self, compat: bool) -> Self {
        self.compat = compat;
        self
    }
}

impl Widget for DetailsPane<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let (border_style, title_style, dimmed_style, default_style, header_style, accent_style, status_online_style, status_offline_style, warning_style) = if self.compat {
            let border = if self.focused { Compat::border_focused() } else { Compat::border() };
            (border, Compat::title(), Compat::dimmed(), Compat::default(), Compat::header(), Compat::accent(), Compat::status_online(), Compat::status_offline(), Compat::warning())
        } else {
            let border = if self.focused { Theme::border_focused() } else { Theme::border() };
            (border, Theme::title(), Theme::dimmed(), Theme::default(), Theme::header(), Style::default().fg(Theme::ACCENT), Theme::status_online(), Theme::status_offline(), Style::default().fg(Theme::WARNING))
        };

        let mut block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(" Host Details ")
            .title_style(title_style);
        if self.compat {
            block = block.border_set(Compat::BORDERS);
        }

        let inner = block.inner(area);
        block.render(area, buf);

        let Some(host) = self.host else {
            let empty_msg = Paragraph::new(Line::from(Span::styled(
                "Select a host to view details",
                dimmed_style,
            )));
            empty_msg.render(inner, buf);
            return;
        };

        let mut lines = Vec::new();

        // Cache indicator — shown when this host's data came from a previous scan
        if let Some(scanned_at) = host.cached_at {
            let age = format_cache_age(scanned_at);
            let cache_sym = if self.compat { Compat::SYM_CACHED } else { "◷" };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{} Cached · {}", cache_sym, age),
                    warning_style,
                ),
            ]));
            lines.push(Line::from(""));
        }

        // IP Address
        lines.push(Line::from(vec![
            Span::styled("IP:       ", dimmed_style),
            Span::styled(host.ip.to_string(), default_style),
        ]));

        // Status
        let status_style = if host.is_alive { status_online_style } else { status_offline_style };
        let status_text = if host.is_alive { "Online" } else { "Offline" };
        lines.push(Line::from(vec![
            Span::styled("Status:   ", dimmed_style),
            Span::styled(status_text, status_style),
        ]));

        // RTT
        if let Some(rtt) = host.rtt {
            lines.push(Line::from(vec![
                Span::styled("RTT:      ", dimmed_style),
                Span::styled(format!("{}ms", rtt.as_millis()), default_style),
            ]));
        }

        // Hostname
        if let Some(hostname) = &host.hostname {
            lines.push(Line::from(vec![
                Span::styled("Hostname: ", dimmed_style),
                Span::styled(hostname.clone(), default_style),
            ]));
        }

        // MAC Address
        if let Some(mac) = &host.mac {
            let mac_text = if let Some(vendor) = &mac.vendor {
                format!("{} ({})", mac.address, vendor)
            } else {
                mac.address.clone()
            };
            lines.push(Line::from(vec![
                Span::styled("MAC:      ", dimmed_style),
                Span::styled(mac_text, default_style),
            ]));
        }

        // Open Ports
        lines.push(Line::from(""));
        if self.port_scanning {
            lines.push(Line::from(Span::styled("Scanning ports...", dimmed_style)));
        } else if host.open_ports.is_empty() {
            if host.ports_scanned && host.is_alive {
                lines.push(Line::from(Span::styled("No open ports found", dimmed_style)));
            }
        } else {
            lines.push(Line::from(Span::styled("Open Ports:", header_style)));
            for port in &host.open_ports {
                let service = get_service_name(*port);
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:5} ", port), accent_style),
                    Span::styled(service, dimmed_style),
                ]));
            }
        }

        let paragraph = Paragraph::new(lines);
        paragraph.render(inner, buf);
    }
}

