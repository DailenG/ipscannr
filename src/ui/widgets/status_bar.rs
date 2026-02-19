use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::Widget,
};

use crate::ui::theme::Theme;

pub struct StatusBar<'a> {
    hotkeys: Vec<(&'a str, &'a str)>,
    status_left: Option<String>,
    status_right: Option<String>,
}

impl<'a> StatusBar<'a> {
    pub fn new() -> Self {
        Self {
            hotkeys: vec![
                ("S", "Scan"),
                ("R", "Range"),
                ("P", "Ports"),
                ("F", "Filter"),
                ("E", "Export"),
                ("?", "Help"),
                ("Q", "Quit"),
            ],
            status_left: None,
            status_right: None,
        }
    }

    pub fn compact() -> Self {
        Self {
            hotkeys: vec![
                ("S", "Scan"),
                ("Q", "Quit"),
                ("?", "Help"),
            ],
            status_left: None,
            status_right: None,
        }
    }

    pub fn status_left(mut self, status: impl Into<String>) -> Self {
        self.status_left = Some(status.into());
        self
    }

    pub fn status_right(mut self, status: impl Into<String>) -> Self {
        self.status_right = Some(status.into());
        self
    }

    pub fn hotkeys(mut self, hotkeys: Vec<(&'a str, &'a str)>) -> Self {
        self.hotkeys = hotkeys;
        self
    }
}

impl Default for StatusBar<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl Widget for StatusBar<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Build hotkey spans
        let mut hotkey_spans = Vec::new();
        for (i, (key, desc)) in self.hotkeys.iter().enumerate() {
            if i > 0 {
                hotkey_spans.push(Span::styled(" ", Theme::default()));
            }
            hotkey_spans.push(Span::styled(format!("[{}]", key), Theme::hotkey()));
            hotkey_spans.push(Span::styled(*desc, Theme::hotkey_desc()));
        }

        let chunks = Layout::horizontal([
            Constraint::Min(20),
            Constraint::Length(30),
        ])
        .split(area);

        // Render status_left (dim hint) if set, otherwise render hotkeys
        if let Some(left) = self.status_left {
            let left_line = Line::from(Span::styled(left, Theme::dimmed()));
            buf.set_line(chunks[0].x, chunks[0].y, &left_line, chunks[0].width);
        } else {
            let hotkey_line = Line::from(hotkey_spans);
            buf.set_line(chunks[0].x, chunks[0].y, &hotkey_line, chunks[0].width);
        }

        // Render status on the right
        if let Some(status) = self.status_right {
            let status_line = Line::from(Span::styled(status, Theme::dimmed()));
            let x = chunks[1].x + chunks[1].width.saturating_sub(status_line.width() as u16);
            buf.set_line(x, chunks[1].y, &status_line, chunks[1].width);
        }
    }
}
