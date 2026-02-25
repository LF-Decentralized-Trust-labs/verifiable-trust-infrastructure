use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier},
    widgets::Widget,
};

// ── ANSI constants ──────────────────────────────────────────────────

pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const GREEN: &str = "\x1b[32m";
pub const RED: &str = "\x1b[31m";
pub const CYAN: &str = "\x1b[36m";
pub const YELLOW: &str = "\x1b[33m";
pub const RESET: &str = "\x1b[0m";

// ── Ratatui rendering helpers ───────────────────────────────────────

pub fn print_widget(widget: impl Widget, height: u16) {
    let width = ratatui::crossterm::terminal::size().map_or(120, |(w, _)| w);
    let area = Rect::new(0, 0, width, height);
    let mut buf = Buffer::empty(area);
    widget.render(area, &mut buf);

    let mut out = String::new();
    for y in 0..height {
        let mut cur_fg = Color::Reset;
        let mut cur_bg = Color::Reset;
        let mut cur_mod = Modifier::empty();

        for x in 0..width {
            let cell = &buf[(x, y)];
            if cell.skip {
                continue;
            }

            if cell.fg != cur_fg || cell.bg != cur_bg || cell.modifier != cur_mod {
                out.push_str("\x1b[0m");
                push_ansi_fg(&mut out, cell.fg);
                push_ansi_bg(&mut out, cell.bg);
                push_ansi_mod(&mut out, cell.modifier);
                cur_fg = cell.fg;
                cur_bg = cell.bg;
                cur_mod = cell.modifier;
            }

            out.push_str(cell.symbol());
        }
        out.push_str("\x1b[0m\n");
    }

    print!("{out}");
}

pub fn push_ansi_fg(out: &mut String, color: Color) {
    use std::fmt::Write as _;
    match color {
        Color::Reset => {}
        Color::Black => out.push_str("\x1b[30m"),
        Color::Red => out.push_str("\x1b[31m"),
        Color::Green => out.push_str("\x1b[32m"),
        Color::Yellow => out.push_str("\x1b[33m"),
        Color::Blue => out.push_str("\x1b[34m"),
        Color::Magenta => out.push_str("\x1b[35m"),
        Color::Cyan => out.push_str("\x1b[36m"),
        Color::Gray => out.push_str("\x1b[37m"),
        Color::DarkGray => out.push_str("\x1b[90m"),
        Color::LightRed => out.push_str("\x1b[91m"),
        Color::LightGreen => out.push_str("\x1b[92m"),
        Color::LightYellow => out.push_str("\x1b[93m"),
        Color::LightBlue => out.push_str("\x1b[94m"),
        Color::LightMagenta => out.push_str("\x1b[95m"),
        Color::LightCyan => out.push_str("\x1b[96m"),
        Color::White => out.push_str("\x1b[97m"),
        Color::Rgb(r, g, b) => {
            let _ = write!(out, "\x1b[38;2;{r};{g};{b}m");
        }
        Color::Indexed(i) => {
            let _ = write!(out, "\x1b[38;5;{i}m");
        }
    }
}

pub fn push_ansi_bg(out: &mut String, color: Color) {
    use std::fmt::Write as _;
    match color {
        Color::Reset => {}
        Color::Black => out.push_str("\x1b[40m"),
        Color::Red => out.push_str("\x1b[41m"),
        Color::Green => out.push_str("\x1b[42m"),
        Color::Yellow => out.push_str("\x1b[43m"),
        Color::Blue => out.push_str("\x1b[44m"),
        Color::Magenta => out.push_str("\x1b[45m"),
        Color::Cyan => out.push_str("\x1b[46m"),
        Color::Gray => out.push_str("\x1b[47m"),
        Color::DarkGray => out.push_str("\x1b[100m"),
        Color::LightRed => out.push_str("\x1b[101m"),
        Color::LightGreen => out.push_str("\x1b[102m"),
        Color::LightYellow => out.push_str("\x1b[103m"),
        Color::LightBlue => out.push_str("\x1b[104m"),
        Color::LightMagenta => out.push_str("\x1b[105m"),
        Color::LightCyan => out.push_str("\x1b[106m"),
        Color::White => out.push_str("\x1b[107m"),
        Color::Rgb(r, g, b) => {
            let _ = write!(out, "\x1b[48;2;{r};{g};{b}m");
        }
        Color::Indexed(i) => {
            let _ = write!(out, "\x1b[48;5;{i}m");
        }
    }
}

pub fn push_ansi_mod(out: &mut String, modifier: Modifier) {
    if modifier.contains(Modifier::BOLD) {
        out.push_str("\x1b[1m");
    }
    if modifier.contains(Modifier::DIM) {
        out.push_str("\x1b[2m");
    }
    if modifier.contains(Modifier::ITALIC) {
        out.push_str("\x1b[3m");
    }
    if modifier.contains(Modifier::UNDERLINED) {
        out.push_str("\x1b[4m");
    }
    if modifier.contains(Modifier::REVERSED) {
        out.push_str("\x1b[7m");
    }
    if modifier.contains(Modifier::CROSSED_OUT) {
        out.push_str("\x1b[9m");
    }
}

pub fn print_section(title: &str) {
    let pad = 46usize.saturating_sub(title.len());
    println!(
        "\n{DIM}──{RESET} {BOLD}{title}{RESET} {DIM}{}{RESET}",
        "─".repeat(pad)
    );
}
