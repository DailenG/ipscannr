use std::collections::HashSet;
use std::net::Ipv4Addr;

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Row, StatefulWidget, Table, TableState},
};

use crate::app::HostInfo;
use crate::ui::theme::{Compat, Theme};

pub struct ScanTable<'a> {
    hosts: &'a [HostInfo],
    show_rtt: bool,
    focused: bool,
    selected_ips: Option<&'a HashSet<Ipv4Addr>>,
    compat: bool,
}

impl<'a> ScanTable<'a> {
    pub fn new(hosts: &'a [HostInfo]) -> Self {
        Self {
            hosts,
            show_rtt: true,
            focused: true,
            selected_ips: None,
            compat: false,
        }
    }

    pub fn show_rtt(mut self, show: bool) -> Self {
        self.show_rtt = show;
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn selected_ips(mut self, ips: &'a HashSet<Ipv4Addr>) -> Self {
        self.selected_ips = Some(ips);
        self
    }

    pub fn compat(mut self, compat: bool) -> Self {
        self.compat = compat;
        self
    }
}

impl<'a> StatefulWidget for ScanTable<'a> {
    type State = TableState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let header_cells = if self.show_rtt {
            vec!["IP", "STATUS", "HOSTNAME", "RTT"]
        } else {
            vec!["IP", "STATUS", "HOSTNAME"]
        };

        let header_style = if self.compat { Compat::header() } else { Theme::header() };
        let header = Row::new(header_cells)
            .style(header_style)
            .height(1);

        let rows: Vec<Row> = self
            .hosts
            .iter()
            .map(|host| {
                let is_selected = self
                    .selected_ips
                    .is_some_and(|s| s.contains(&host.ip));

                let ip_cell = if is_selected {
                    let (sel_sym, sel_style) = if self.compat {
                        ("x ", Compat::accent())
                    } else {
                        ("✓ ", Style::default().fg(Theme::SUCCESS))
                    };
                    Line::from(vec![
                        Span::styled(sel_sym, sel_style),
                        Span::raw(host.ip.to_string()),
                    ])
                } else {
                    Line::from(host.ip.to_string())
                };

                let status_span = if self.compat {
                    if host.is_alive {
                        Span::styled(Compat::SYM_ONLINE, Compat::status_online())
                    } else {
                        Span::styled(Compat::SYM_OFFLINE, Compat::status_offline())
                    }
                } else if host.is_alive {
                    Span::styled("●", Theme::status_online())
                } else {
                    Span::styled("○", Theme::status_offline())
                };

                // Fall back to MAC vendor when no hostname is resolved
                let (hostname_text, hostname_style) = if let Some(name) = host.hostname.as_deref() {
                    let style = if self.compat { Compat::default() } else { Theme::default() };
                    (name.to_string(), style)
                } else if let Some(vendor) = host.mac.as_ref().and_then(|m| m.vendor.as_deref()) {
                    let style = if self.compat { Compat::dimmed() } else { Theme::dimmed() };
                    (format!("[{}]", vendor), style)
                } else {
                    let style = if self.compat { Compat::default() } else { Theme::default() };
                    ("-".to_string(), style)
                };

                let row_style = if self.compat { Compat::default() } else { Theme::default() };
                let cells: Vec<Line> = if self.show_rtt {
                    let rtt = host
                        .rtt
                        .map(|d| format!("{}ms", d.as_millis()))
                        .unwrap_or_else(|| "-".to_string());

                    vec![
                        ip_cell,
                        Line::from(status_span),
                        Line::from(Span::styled(hostname_text, hostname_style)),
                        Line::from(rtt),
                    ]
                } else {
                    vec![
                        ip_cell,
                        Line::from(status_span),
                        Line::from(Span::styled(hostname_text, hostname_style)),
                    ]
                };

                Row::new(cells).style(row_style)
            })
            .collect();

        let widths = if self.show_rtt {
            [
                ratatui::layout::Constraint::Length(18),
                ratatui::layout::Constraint::Length(8),
                ratatui::layout::Constraint::Min(15),
                ratatui::layout::Constraint::Length(8),
            ]
            .as_slice()
        } else {
            [
                ratatui::layout::Constraint::Length(18),
                ratatui::layout::Constraint::Length(8),
                ratatui::layout::Constraint::Min(15),
            ]
            .as_slice()
        };

        let (border_style, title_style, highlight_style, cursor_sym) = if self.compat {
            let border = if self.focused { Compat::border_focused() } else { Compat::border() };
            (border, Compat::title(), Compat::selected(), Compat::SYM_CURSOR)
        } else {
            let border = if self.focused { Theme::border_focused() } else { Theme::border() };
            (border, Theme::title(), Theme::selected(), "▶ ")
        };

        let mut block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(" Hosts ")
            .title_style(title_style);
        if self.compat {
            block = block.border_set(Compat::BORDERS);
        }

        let table = Table::new(rows, widths)
            .header(header)
            .block(block)
            .row_highlight_style(highlight_style)
            .highlight_symbol(cursor_sym);

        StatefulWidget::render(table, area, buf, state);
    }
}
