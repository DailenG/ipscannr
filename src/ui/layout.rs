use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Layout mode based on terminal size
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LayoutMode {
    Compact,
    Full,
}

impl LayoutMode {
    pub fn from_size(width: u16, height: u16) -> Self {
        if width >= 100 && height >= 30 {
            LayoutMode::Full
        } else {
            LayoutMode::Compact
        }
    }
}

/// Layout areas for the application
#[derive(Debug, Clone)]
pub struct AppLayout {
    pub mode: LayoutMode,
    pub header: Rect,
    pub main: Rect,
    pub hosts_table: Rect,
    pub details_pane: Option<Rect>,
    pub status_bar: Rect,
}

impl AppLayout {
    pub fn new(area: Rect) -> Self {
        let mode = LayoutMode::from_size(area.width, area.height);

        let vertical = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header with input
                Constraint::Min(10),   // Main content
                Constraint::Length(1), // Status bar
            ])
            .split(area);

        let header = vertical[0];
        let main = vertical[1];
        let status_bar = vertical[2];

        let (hosts_table, details_pane) = match mode {
            LayoutMode::Compact => (main, None),
            LayoutMode::Full => {
                let horizontal = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Percentage(55),
                        Constraint::Percentage(45),
                    ])
                    .split(main);

                (horizontal[0], Some(horizontal[1]))
            }
        };

        Self {
            mode,
            header,
            main,
            hosts_table,
            details_pane,
            status_bar,
        }
    }

    pub fn is_compact(&self) -> bool {
        self.mode == LayoutMode::Compact
    }

    pub fn is_full(&self) -> bool {
        self.mode == LayoutMode::Full
    }
}
