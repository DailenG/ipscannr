use ratatui::{
    buffer::Buffer,
    layout::Rect,
    text::Span,
    widgets::Widget,
};

use crate::ui::theme::{Compat, Theme};

pub struct ProgressBar {
    progress: f64, // 0.0 to 1.0
    label: Option<String>,
    show_percentage: bool,
    compat: bool,
}

impl ProgressBar {
    pub fn new(progress: f64) -> Self {
        Self {
            progress: progress.clamp(0.0, 1.0),
            label: None,
            show_percentage: true,
            compat: false,
        }
    }

    #[allow(dead_code)]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn show_percentage(mut self, show: bool) -> Self {
        self.show_percentage = show;
        self
    }

    pub fn compat(mut self, compat: bool) -> Self {
        self.compat = compat;
        self
    }
}

impl Widget for ProgressBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 {
            return;
        }

        // Calculate label and percentage width
        let label_text = self.label.unwrap_or_default();
        let percentage_text = if self.show_percentage {
            format!(" {:3.0}%", self.progress * 100.0)
        } else {
            String::new()
        };

        let label_width = label_text.len() as u16;
        let percentage_width = percentage_text.len() as u16;
        let bar_width = area
            .width
            .saturating_sub(label_width + percentage_width + 3); // 3 for [] and space

        if bar_width < 1 {
            return;
        }

        let mut x = area.x;

        // Draw label
        if !label_text.is_empty() {
            let lbl_style = if self.compat { Compat::default() } else { Theme::default() };
            let label_span = Span::styled(&label_text, lbl_style);
            buf.set_span(x, area.y, &label_span, label_width);
            x += label_width + 1;
        }

        // Draw progress bar
        let filled_width = (bar_width as f64 * self.progress).round() as u16;
        let empty_width = bar_width.saturating_sub(filled_width);

        let (fill_ch, empty_ch, bar_style, bg_style, bracket_style, pct_style) = if self.compat {
            (
                Compat::SYM_PROGRESS_FILL,
                Compat::SYM_PROGRESS_EMPTY,
                Compat::progress_bar(),
                Compat::progress_bg(),
                Compat::border(),
                Compat::dimmed(),
            )
        } else {
            (
                "█",
                "░",
                Theme::progress_bar(),
                Theme::progress_bg(),
                Theme::border(),
                Theme::dimmed(),
            )
        };

        // Opening bracket
        buf.set_string(x, area.y, "[", bracket_style);
        x += 1;

        // Filled portion
        let filled_str: String = fill_ch.repeat(filled_width as usize);
        let filled_span = Span::styled(filled_str, bar_style);
        buf.set_span(x, area.y, &filled_span, filled_width);
        x += filled_width;

        // Empty portion
        let empty_str: String = empty_ch.repeat(empty_width as usize);
        let empty_span = Span::styled(empty_str, bg_style);
        buf.set_span(x, area.y, &empty_span, empty_width);
        x += empty_width;

        // Closing bracket
        buf.set_string(x, area.y, "]", bracket_style);
        x += 1;

        // Percentage
        if self.show_percentage {
            let pct_span = Span::styled(percentage_text, pct_style);
            buf.set_span(x, area.y, &pct_span, percentage_width);
        }
    }
}
