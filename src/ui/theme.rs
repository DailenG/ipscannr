use ratatui::style::{Color, Modifier, Style};

/// Minimal dark color palette
pub struct Theme;

impl Theme {
    // Base colors
    pub const BG: Color = Color::Rgb(18, 18, 24);
    pub const FG: Color = Color::Rgb(200, 200, 210);
    pub const ACCENT: Color = Color::Rgb(100, 149, 237);
    pub const SUCCESS: Color = Color::Rgb(80, 200, 120);
    pub const ERROR: Color = Color::Rgb(220, 80, 80);
    pub const WARNING: Color = Color::Rgb(230, 180, 80);
    pub const DIM: Color = Color::Rgb(90, 90, 100);
    pub const BORDER: Color = Color::Rgb(60, 60, 70);
    pub const HIGHLIGHT_BG: Color = Color::Rgb(40, 40, 55);

    // Common styles
    pub fn default() -> Style {
        Style::default().fg(Self::FG).bg(Self::BG)
    }

    pub fn title() -> Style {
        Style::default()
            .fg(Self::ACCENT)
            .add_modifier(Modifier::BOLD)
    }

    pub fn border() -> Style {
        Style::default().fg(Self::BORDER)
    }

    pub fn border_focused() -> Style {
        Style::default().fg(Self::ACCENT)
    }

    pub fn status_online() -> Style {
        Style::default().fg(Self::SUCCESS)
    }

    pub fn status_offline() -> Style {
        Style::default().fg(Self::DIM)
    }

    pub fn status_scanning() -> Style {
        Style::default()
            .fg(Self::WARNING)
            .add_modifier(Modifier::SLOW_BLINK)
    }

    pub fn selected() -> Style {
        Style::default()
            .bg(Self::HIGHLIGHT_BG)
            .fg(Self::FG)
            .add_modifier(Modifier::BOLD)
    }

    pub fn dimmed() -> Style {
        Style::default().fg(Self::DIM)
    }

    pub fn error() -> Style {
        Style::default().fg(Self::ERROR)
    }

    pub fn hotkey() -> Style {
        Style::default()
            .fg(Self::ACCENT)
            .add_modifier(Modifier::BOLD)
    }

    pub fn hotkey_desc() -> Style {
        Style::default().fg(Self::DIM)
    }

    pub fn header() -> Style {
        Style::default()
            .fg(Self::ACCENT)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    }

    pub fn progress_bar() -> Style {
        Style::default().fg(Self::ACCENT)
    }

    pub fn progress_bg() -> Style {
        Style::default().fg(Self::BORDER)
    }
}
