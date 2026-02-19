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
use crate::ui::theme::Theme;

pub struct DetailsPane<'a> {
    host: Option<&'a HostInfo>,
    focused: bool,
}

impl<'a> DetailsPane<'a> {
    pub fn new(host: Option<&'a HostInfo>) -> Self {
        Self {
            host,
            focused: false,
        }
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }
}

impl Widget for DetailsPane<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let border_style = if self.focused {
            Theme::border_focused()
        } else {
            Theme::border()
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(" Host Details ")
            .title_style(Theme::title());

        let inner = block.inner(area);
        block.render(area, buf);

        let Some(host) = self.host else {
            let empty_msg = Paragraph::new(Line::from(Span::styled(
                "Select a host to view details",
                Theme::dimmed(),
            )));
            empty_msg.render(inner, buf);
            return;
        };

        let mut lines = Vec::new();

        // Cache indicator — shown when this host's data came from a previous scan
        if let Some(scanned_at) = host.cached_at {
            let age = format_cache_age(scanned_at);
            lines.push(Line::from(vec![
                Span::styled(
                    format!("◷ Cached · {}", age),
                    Style::default().fg(Theme::WARNING),
                ),
            ]));
            lines.push(Line::from(""));
        }

        // IP Address
        lines.push(Line::from(vec![
            Span::styled("IP:       ", Theme::dimmed()),
            Span::styled(host.ip.to_string(), Theme::default()),
        ]));

        // Status
        let status_style = if host.is_alive {
            Theme::status_online()
        } else {
            Theme::status_offline()
        };
        let status_text = if host.is_alive { "Online" } else { "Offline" };
        lines.push(Line::from(vec![
            Span::styled("Status:   ", Theme::dimmed()),
            Span::styled(status_text, status_style),
        ]));

        // RTT
        if let Some(rtt) = host.rtt {
            lines.push(Line::from(vec![
                Span::styled("RTT:      ", Theme::dimmed()),
                Span::styled(format!("{}ms", rtt.as_millis()), Theme::default()),
            ]));
        }

        // Hostname
        if let Some(hostname) = &host.hostname {
            lines.push(Line::from(vec![
                Span::styled("Hostname: ", Theme::dimmed()),
                Span::styled(hostname.clone(), Theme::default()),
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
                Span::styled("MAC:      ", Theme::dimmed()),
                Span::styled(mac_text, Theme::default()),
            ]));
        }

        // Open Ports
        if !host.open_ports.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Open Ports:", Theme::header())));

            for port in &host.open_ports {
                let service = get_service_name(*port);
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:5} ", port), Theme::accent()),
                    Span::styled(service, Theme::dimmed()),
                ]));
            }
        }

        let paragraph = Paragraph::new(lines);
        paragraph.render(inner, buf);
    }
}

// Helper trait for theme
trait ThemeExt {
    fn accent() -> ratatui::style::Style;
}

impl ThemeExt for Theme {
    fn accent() -> ratatui::style::Style {
        ratatui::style::Style::default().fg(Theme::ACCENT)
    }
}
