use std::fmt;

use colored::{ColoredString, Colorize};

pub struct ColoredGroup {
    items: Vec<ColoredString>,
}

impl ColoredGroup {
    pub fn new() -> Self {
        Self { items: vec![] }
    }

    pub fn push<S: Into<ColoredString>>(mut self, item: S) -> Self {
        self.items.push(item.into());

        self
    }

    pub fn space(self) -> Self {
        self.push(" ")
    }

    pub fn newline(self) -> Self {
        self.push("\n")
    }

    pub fn absorb<F: Fn(ColoredString) -> ColoredString>(
        mut self,
        other: Self,
        transformation: Option<F>,
    ) -> Self {
        for item in other.items {
            let transformed = if let Some(f) = &transformation {
                f(item)
            } else {
                item
            };

            self.items.push(transformed)
        }

        self
    }

    pub fn len(&self) -> usize {
        self.items.iter().map(|s| s.len()).sum()
    }
}

impl fmt::Display for ColoredGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for item in &self.items {
            item.fmt(f)?
        }

        Ok(())
    }
}

impl<T: Into<ColoredString>> From<T> for ColoredGroup {
    fn from(s: T) -> Self {
        Self {
            items: vec![s.into()],
        }
    }
}

pub fn build_header<T: Into<ColoredGroup>>(title: T) -> ColoredGroup {
    let title = title.into();
    let width = title.len() + 2 * 6;

    ColoredGroup::new()
        .push("#".repeat(width).yellow())
        .newline()
        .push("#".repeat(5).yellow())
        .space()
        .absorb(title, Some(ColoredString::bold))
        .space()
        .push("#".repeat(5).yellow())
        .newline()
        .push("#".repeat(width).yellow())
        .newline()
}
