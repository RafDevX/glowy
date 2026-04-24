use colored::Colorize;

pub fn build_header(title: impl ToString) -> String {
    let title = title.to_string();

    let width = ansi_ignoring_len(&title) + 2 * 6;

    format!(
        "{}\n{} {} {}\n{}\n",
        "#".repeat(width).yellow(),
        "#".repeat(5).yellow(),
        title.bold(),
        "#".repeat(5).yellow(),
        "#".repeat(width).yellow()
    )
}

fn ansi_ignoring_len(s: &str) -> usize {
    let mut inside = false;
    let mut code_bytes = 0;

    for byte in s.bytes() {
        if inside {
            if byte == b'm' {
                inside = false;
            }

            code_bytes += 1;
        } else if byte == 0x1b {
            inside = true;
            code_bytes += 1;
        } else {
            // normal character, not part of a control code
        }
    }

    s.len().saturating_sub(code_bytes)
}
