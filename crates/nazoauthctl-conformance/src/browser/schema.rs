use std::fmt;

use zeroize::Zeroizing;

/// A Suite `browser` entry. Secret values are kept only in `BrowserCommand`;
/// this structure intentionally has no custom Debug implementation that could
/// expose them.
pub struct BrowserEntry {
    pub match_pattern: String,
    pub match_limit: Option<u32>,
    pub tasks: Vec<BrowserTask>,
}

impl fmt::Debug for BrowserEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserEntry")
            .field("match_pattern", &self.match_pattern)
            .field("match_limit", &self.match_limit)
            .field("tasks", &self.tasks.len())
            .finish()
    }
}

pub struct BrowserTask {
    pub task: Option<String>,
    pub optional: bool,
    pub match_pattern: Option<String>,
    pub commands: Vec<BrowserCommand>,
}

impl fmt::Debug for BrowserTask {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserTask")
            .field("task", &self.task)
            .field("optional", &self.optional)
            .field("match_pattern", &self.match_pattern)
            .field("commands", &self.commands.len())
            .finish()
    }
}

/// A parsed selector accepted by WebDriver. `contains` is handled by the
/// parser as text/URL matching and is never passed to a driver as CSS.
#[derive(Clone, Eq, PartialEq)]
pub enum BrowserSelector {
    Id(String),
    Css(String),
}

impl fmt::Debug for BrowserSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Id(_) => "Id(<redacted>)",
            Self::Css(_) => "Css(<redacted>)",
        })
    }
}

/// The supported subset of official Suite browser command tuples.
pub enum BrowserCommand {
    WaitForElement {
        selector: BrowserSelector,
        timeout: std::time::Duration,
        text_pattern: Option<String>,
    },
    WaitElementVisible {
        selector: BrowserSelector,
        timeout: std::time::Duration,
    },
    WaitContains {
        needle: String,
        timeout: std::time::Duration,
    },
    Text {
        selector: BrowserSelector,
        value: Zeroizing<String>,
    },
    Click {
        selector: BrowserSelector,
    },
}

impl fmt::Debug for BrowserCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::WaitForElement { .. } => "wait",
            Self::WaitElementVisible { .. } => "wait-element-visible",
            Self::WaitContains { .. } => "wait-contains",
            Self::Text { .. } => "text",
            Self::Click { .. } => "click",
        };
        formatter.write_str(kind)
    }
}
