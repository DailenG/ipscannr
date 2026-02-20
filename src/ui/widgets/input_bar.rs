use ratatui::{
    buffer::Buffer,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};

use crate::ui::theme::{Compat, Theme};

pub struct InputBar<'a> {
    label: &'a str,
    value: &'a str,
    cursor_position: usize,
    focused: bool,
    compat: bool,
}

impl<'a> InputBar<'a> {
    pub fn new(label: &'a str, value: &'a str) -> Self {
        Self {
            label,
            value,
            cursor_position: value.len(),
            focused: false,
            compat: false,
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

    pub fn compat(mut self, compat: bool) -> Self {
        self.compat = compat;
        self
    }
}

impl Widget for InputBar<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let (border_style, title_style, text_style, cursor_style) = if self.compat {
            let border = if self.focused { Compat::border_focused() } else { Compat::border() };
            (border, Compat::title(), Compat::default(), Compat::selected())
        } else {
            let border = if self.focused { Theme::border_focused() } else { Theme::border() };
            (border, Theme::title(), Theme::default(), Theme::selected())
        };

        let mut block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(format!(" {} ", self.label))
            .title_style(title_style);
        if self.compat {
            block = block.border_set(Compat::BORDERS);
        }

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
                Span::styled(before, text_style),
                Span::styled(cursor_char.to_string(), cursor_style),
                Span::styled(rest, text_style),
            ])
        } else {
            Line::from(Span::styled(self.value, text_style))
        };

        let paragraph = Paragraph::new(display_value);
        paragraph.render(inner, buf);
    }
}
