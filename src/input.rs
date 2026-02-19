use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Actions that can be performed in the application
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Action {
    Quit,
    StartScan,
    StopScan,
    EditRange,
    ConfigurePorts,
    ToggleFilter,
    Export,
    ToggleDetails,
    Help,
    NavigateUp,
    NavigateDown,
    NavigatePageUp,
    NavigatePageDown,
    NavigateHome,
    NavigateEnd,
    Select,
    ToggleSelect, // Spacebar: multi-select hosts (or resume paused scan)
    Cancel,
    SwitchPane,
    Delete,
    Backspace,
    Character(char),
    // Host Details actions
    WakeOnLan,
    ContinuousPing,
    RunTracert,
    SaveHost,
    StopOverlay, // Close output overlay (ping/tracert)
    None,
}

/// Current input mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputMode {
    Normal,
    EditingRange,
    EditingPorts,
    Help,
    Exporting,
    OutputOverlay, // Streaming output for continuous ping / tracert
}

/// Map key events to actions based on current mode
pub fn handle_key(key: KeyEvent, mode: InputMode) -> Action {
    match mode {
        InputMode::Normal => handle_normal_mode(key),
        InputMode::EditingRange | InputMode::EditingPorts => handle_editing_mode(key),
        InputMode::Help => handle_help_mode(key),
        InputMode::Exporting => handle_export_mode(key),
        InputMode::OutputOverlay => handle_overlay_mode(key),
    }
}

fn handle_normal_mode(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Esc => Action::Cancel, // Pause scan or switch panes
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Action::Quit,
        KeyCode::Char('s') => Action::StartScan,
        KeyCode::Char('x') => Action::StopScan,
        KeyCode::Char('r') => Action::EditRange,
        KeyCode::Char('p') => Action::ConfigurePorts,
        KeyCode::Char('f') => Action::ToggleFilter,
        KeyCode::Char('e') => Action::Export,
        KeyCode::Char('d') => Action::ToggleDetails,
        KeyCode::Char('?') => Action::Help,
        KeyCode::Char('w') => Action::WakeOnLan,
        KeyCode::Char('c') => Action::ContinuousPing, // non-Ctrl c
        KeyCode::Char('t') => Action::RunTracert,
        KeyCode::Char('a') => Action::SaveHost,
        KeyCode::Char(' ') => Action::ToggleSelect, // Space: multi-select or resume
        KeyCode::Up | KeyCode::Char('k') => Action::NavigateUp,
        KeyCode::Down | KeyCode::Char('j') => Action::NavigateDown,
        KeyCode::PageUp => Action::NavigatePageUp,
        KeyCode::PageDown => Action::NavigatePageDown,
        KeyCode::Home => Action::NavigateHome,
        KeyCode::End => Action::NavigateEnd,
        KeyCode::Enter => Action::Select,
        KeyCode::Tab => Action::SwitchPane,
        KeyCode::Backspace => Action::Backspace, // Enter edit mode from range pane
        KeyCode::Char(c) => Action::Character(c), // Pass unbound chars through (digits, punctuation, etc.)
        _ => Action::None,
    }
}

fn handle_editing_mode(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Esc => Action::Cancel,
        KeyCode::Enter => Action::Select,
        KeyCode::Backspace => Action::Backspace,
        KeyCode::Delete => Action::Delete,
        KeyCode::Left => Action::NavigateUp,
        KeyCode::Right => Action::NavigateDown,
        KeyCode::Home => Action::NavigateHome,
        KeyCode::End => Action::NavigateEnd,
        KeyCode::Char(c) => Action::Character(c),
        _ => Action::None,
    }
}

fn handle_help_mode(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') | KeyCode::Enter => Action::Cancel,
        _ => Action::None,
    }
}

fn handle_export_mode(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Esc => Action::Cancel,
        KeyCode::Char('c') => Action::Character('c'), // CSV
        KeyCode::Char('j') => Action::Character('j'), // JSON
        _ => Action::None,
    }
}

fn handle_overlay_mode(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => Action::StopOverlay,
        KeyCode::Up | KeyCode::Char('k') => Action::NavigateUp,
        KeyCode::Down | KeyCode::Char('j') => Action::NavigateDown,
        KeyCode::Home => Action::NavigateHome,
        KeyCode::End => Action::NavigateEnd,
        _ => Action::None,
    }
}
