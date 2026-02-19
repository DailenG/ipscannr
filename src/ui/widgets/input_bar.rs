use ratatui::{
    buffer::Buffer,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};

use crate::ui::theme::Theme;

pub struct InputBar<'a> {
    label: &'a str,
    value: &'a str,
    cursor_position: usize,
    focused: bool,
}

impl<'a> InputBar<'a> {
    pub fn new(label: &'a str, value: &'a str) -> Self {
        Self {
            label,
            value,
            cursor_position: value.len(),
            focused: false,
        }
    }

    pub fn cursor_position(mut self, pos: usize) -> Self {
        self.cursor_position = pos;
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }
}

impl Widget for InputBar<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let border_style = if self.focused {
            Theme::border_focused()
        } else {
            Theme::border()
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(format!(" {} ", self.label))
            .title_style(Theme::title());

        let inner = block.inner(area);
        block.render(area, buf);

        // Render the input value with cursor
        let display_value = if self.focused {
            let (before, after) = self.value.split_at(self.cursor_position.min(self.value.len()));
            let cursor_char = after.chars().next().unwrap_or(' ');
            let rest = if after.is_empty() {
                ""
            } else {
                &after[cursor_char.len_utf8()..]
            };

            Line::from(vec![
                Span::styled(before, Theme::default()),
                Span::styled(
                    cursor_char.to_string(),
                    Theme::selected(),
                ),
                Span::styled(rest, Theme::default()),
            ])
        } else {
            Line::from(Span::styled(self.value, Theme::default()))
        };

        let paragraph = Paragraph::new(display_value);
        paragraph.render(inner, buf);
    }
}
