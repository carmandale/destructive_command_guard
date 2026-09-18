//! Table rendering for dcg.
//!
//! Provides formatted table output for scan results, statistics, and pack listings.
//! Automatically adapts to terminal width and supports multiple output styles.
//!
//! # Supported Tables
//!
//! - `ScanResultsTable` - Scan findings with file, line, severity, pattern
//! - `StatsTable` - Rule statistics with hits, outcomes, rates
//! - `PackListTable` - Pack listings with ID, name, pattern counts
//!
//! # Output Styles
//!
//! - Unicode (default for TTY) - Box-drawing characters
//! - ASCII - Portable ASCII characters
//! - Markdown - GitHub-flavored markdown tables
//! - Compact - Minimal spacing for dense output

use comfy_table::presets;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Row, Table};
use ratatui::style::Color as RatColor;

use super::theme::{BorderStyle, Severity, Theme};

/// Convert ratatui color to comfy-table color.
fn to_table_color(color: RatColor) -> Color {
    match color {
        RatColor::Reset => Color::Reset,
        RatColor::Black => Color::Black,
        RatColor::Red => Color::Red,
        RatColor::Green => Color::Green,
        RatColor::Yellow => Color::Yellow,
        RatColor::Blue => Color::Blue,
        RatColor::Magenta => Color::Magenta,
        RatColor::Cyan => Color::Cyan,
        RatColor::Gray => Color::Grey,
        RatColor::DarkGray => Color::DarkGrey,
        RatColor::LightRed => Color::Red,
        RatColor::LightGreen => Color::Green,
        RatColor::LightYellow => Color::Yellow,
        RatColor::LightBlue => Color::Blue,
        RatColor::LightMagenta => Color::Magenta,
        RatColor::LightCyan => Color::Cyan,
        RatColor::White => Color::White,
        RatColor::Rgb(r, g, b) => Color::Rgb { r, g, b },
        RatColor::Indexed(value) => Color::AnsiValue(value),
    }
}

/// Table rendering style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TableStyle {
    /// Unicode box-drawing characters (default for TTY).
    #[default]
    Unicode,
    /// ASCII-only characters for maximum compatibility.
    Ascii,
    /// Markdown table format for documentation.
    Markdown,
    /// Compact output with minimal spacing.
    Compact,
}

impl TableStyle {
    /// Applies this style's preset to a comfy-table.
    fn apply_preset(&self, table: &mut Table) {
        match self {
            Self::Unicode => {
                table.load_preset(presets::UTF8_FULL);
            }
            Self::Ascii => {
                table.load_preset(presets::ASCII_FULL);
            }
            Self::Markdown => {
                table.load_preset(presets::ASCII_MARKDOWN);
            }
            Self::Compact => {
                table.load_preset(presets::UTF8_BORDERS_ONLY);
            }
        }
    }

    /// Returns true if this style should use Markdown output (comfy-table).
    #[must_use]
    pub const fn is_markdown(&self) -> bool {
        matches!(self, Self::Markdown)
    }
}

impl From<BorderStyle> for TableStyle {
    fn from(border: BorderStyle) -> Self {
        match border {
            BorderStyle::Unicode => Self::Unicode,
            BorderStyle::Ascii => Self::Ascii,
            BorderStyle::None => Self::Compact,
        }
    }
}

/// A single scan result row for table display.
#[derive(Debug, Clone)]
pub struct ScanResultRow {
    /// File path (may be truncated for display).
    pub file: String,
    /// Line number.
    pub line: usize,
    /// Severity level.
    pub severity: Severity,
    /// Pattern/rule ID that matched.
    pub pattern_id: String,
    /// Optional extracted command preview.
    pub command_preview: Option<String>,
}

impl ScanResultRow {
    /// Creates a scan result row from a scan finding.
    ///
    /// Maps `ScanSeverity` to `Severity`:
    /// - Error → High
    /// - Warning → Medium
    /// - Info → Low
    #[must_use]
    pub fn from_scan_finding(finding: &crate::scan::ScanFinding) -> Self {
        let severity = match finding.severity {
            crate::scan::ScanSeverity::Error => Severity::High,
            crate::scan::ScanSeverity::Warning => Severity::Medium,
            crate::scan::ScanSeverity::Info => Severity::Low,
        };

        Self {
            file: finding.file.clone(),
            line: finding.line,
            severity,
            pattern_id: finding
                .rule_id
                .clone()
                .unwrap_or_else(|| finding.extractor_id.clone()),
            command_preview: Some(finding.extracted_command.clone()),
        }
    }
}

/// Table renderer for scan results.
#[derive(Debug)]
pub struct ScanResultsTable {
    rows: Vec<ScanResultRow>,
    style: TableStyle,
    colors_enabled: bool,
    max_width: Option<u16>,
    show_command: bool,
    theme: Option<Theme>,
}

impl ScanResultsTable {
    /// Creates a new scan results table.
    #[must_use]
    pub fn new(rows: Vec<ScanResultRow>) -> Self {
        Self {
            rows,
            style: TableStyle::default(),
            colors_enabled: true,
            max_width: None,
            show_command: false,
            theme: None,
        }
    }

    /// Sets the table style.
    #[must_use]
    pub fn with_style(mut self, style: TableStyle) -> Self {
        self.style = style;
        self
    }

    /// Configures from a theme.
    #[must_use]
    pub fn with_theme(mut self, theme: &Theme) -> Self {
        self.colors_enabled = theme.colors_enabled;
        self.style = theme.border_style.into();
        self.theme = Some(theme.clone());
        self
    }

    /// Sets maximum table width.
    #[must_use]
    pub fn with_max_width(mut self, width: u16) -> Self {
        self.max_width = Some(width);
        self
    }

    /// Enables command preview column.
    #[must_use]
    pub fn with_command_preview(mut self) -> Self {
        self.show_command = true;
        self
    }

    /// Renders the table to a string.
    #[must_use]
    pub fn render(&self) -> String {
        if self.rows.is_empty() {
            return String::from("No findings.");
        }

        self.render_comfy()
    }

    /// Renders using comfy-table (default, or Markdown output).
    fn render_comfy(&self) -> String {
        let mut table = Table::new();
        self.style.apply_preset(&mut table);
        table.set_content_arrangement(ContentArrangement::Dynamic);

        if let Some(width) = self.max_width {
            table.set_width(width);
        }

        // Set header
        let mut header = vec!["File", "Line", "Severity", "Pattern"];
        if self.show_command {
            header.push("Command");
        }
        table.set_header(header);

        // Add rows
        for row in &self.rows {
            let severity_cell = self.severity_cell_comfy(row.severity);
            let mut cells = vec![
                Cell::new(&row.file),
                Cell::new(row.line).set_alignment(CellAlignment::Right),
                severity_cell,
                Cell::new(&row.pattern_id),
            ];

            if self.show_command {
                let cmd = row.command_preview.as_deref().unwrap_or("-");
                let truncated = truncate_with_ellipsis(cmd, 40);
                cells.push(Cell::new(truncated));
            }

            table.add_row(Row::from(cells));
        }

        table.to_string()
    }

    /// Creates a styled cell for severity (comfy-table version).
    fn severity_cell_comfy(&self, severity: Severity) -> Cell {
        let (label, default_color, bold) = match severity {
            Severity::Critical => ("CRIT", Color::Red, true),
            Severity::High => ("HIGH", Color::DarkRed, false),
            Severity::Medium => ("MED", Color::Yellow, false),
            Severity::Low => ("LOW", Color::Blue, false),
        };
        let color = self.theme.as_ref().map_or(default_color, |theme| {
            to_table_color(theme.color_for_severity(severity))
        });

        let mut cell = Cell::new(label);
        if self.colors_enabled {
            cell = cell.fg(color);
            if bold {
                cell = cell.add_attribute(Attribute::Bold);
            }
        }
        cell
    }
}

/// Returns short severity label.
#[cfg(test)]
fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
    }
}

/// A single statistics row for display.
#[derive(Debug, Clone)]
pub struct StatsRow {
    /// Rule/pattern name.
    pub name: String,
    /// Total hit count.
    pub hits: u64,
    /// Number of times allowed.
    pub allowed: u64,
    /// Number of times denied.
    pub denied: u64,
    /// Noise percentage (bypass rate).
    pub noise_pct: Option<f64>,
}

/// Table renderer for rule/pattern statistics.
#[derive(Debug)]
pub struct StatsTable {
    rows: Vec<StatsRow>,
    style: TableStyle,
    colors_enabled: bool,
    max_width: Option<u16>,
    title: Option<String>,
    theme: Option<Theme>,
}

impl StatsTable {
    /// Creates a new stats table.
    #[must_use]
    pub fn new(rows: Vec<StatsRow>) -> Self {
        Self {
            rows,
            style: TableStyle::default(),
            colors_enabled: true,
            max_width: None,
            title: None,
            theme: None,
        }
    }

    /// Sets the table style.
    #[must_use]
    pub fn with_style(mut self, style: TableStyle) -> Self {
        self.style = style;
        self
    }

    /// Configures from a theme.
    #[must_use]
    pub fn with_theme(mut self, theme: &Theme) -> Self {
        self.colors_enabled = theme.colors_enabled;
        self.style = theme.border_style.into();
        self.theme = Some(theme.clone());
        self
    }

    /// Sets maximum table width.
    #[must_use]
    pub fn with_max_width(mut self, width: u16) -> Self {
        self.max_width = Some(width);
        self
    }

    /// Sets an optional title above the table.
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Renders the table to a string.
    #[must_use]
    pub fn render(&self) -> String {
        if self.rows.is_empty() {
            return String::from("No statistics available.");
        }

        self.render_comfy()
    }

    /// Renders using comfy-table (default, or Markdown output).
    fn render_comfy(&self) -> String {
        let mut table = Table::new();
        self.style.apply_preset(&mut table);
        table.set_content_arrangement(ContentArrangement::Dynamic);

        if let Some(width) = self.max_width {
            table.set_width(width);
        }

        // Set header
        table.set_header(vec!["Rule", "Hits", "Allowed", "Denied", "Noise%"]);

        // Add rows
        for row in &self.rows {
            let noise_cell = self.noise_cell_comfy(row.noise_pct);

            table.add_row(Row::from(vec![
                Cell::new(&row.name),
                Cell::new(row.hits).set_alignment(CellAlignment::Right),
                Cell::new(row.allowed).set_alignment(CellAlignment::Right),
                Cell::new(row.denied).set_alignment(CellAlignment::Right),
                noise_cell,
            ]));
        }

        let table_str = table.to_string();

        if let Some(title) = &self.title {
            format!("{title}\n{table_str}")
        } else {
            table_str
        }
    }

    /// Creates a styled cell for noise percentage (comfy-table version).
    fn noise_cell_comfy(&self, noise_pct: Option<f64>) -> Cell {
        let Some(pct) = noise_pct else {
            return Cell::new("-").set_alignment(CellAlignment::Right);
        };

        let label = format!("{pct:.1}%");
        let mut cell = Cell::new(label).set_alignment(CellAlignment::Right);

        if self.colors_enabled {
            let (error_color, warning_color, success_color) =
                self.theme
                    .as_ref()
                    .map_or((Color::Red, Color::Yellow, Color::Green), |theme| {
                        (
                            to_table_color(theme.error_color),
                            to_table_color(theme.warning_color),
                            to_table_color(theme.success_color),
                        )
                    });
            // Color based on noise level: high noise = yellow/red warning
            cell = if pct > 50.0 {
                cell.fg(error_color)
            } else if pct > 25.0 {
                cell.fg(warning_color)
            } else {
                cell.fg(success_color)
            };
        }

        cell
    }
}

/// A single pack row for display.
#[derive(Debug, Clone)]
pub struct PackRow {
    /// Pack ID (e.g., "core.git").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Number of destructive patterns.
    pub destructive_count: usize,
    /// Number of safe patterns.
    pub safe_count: usize,
    /// Whether the pack is enabled.
    pub enabled: bool,
}

/// Table renderer for pack listings.
#[derive(Debug)]
pub struct PackListTable {
    rows: Vec<PackRow>,
    style: TableStyle,
    colors_enabled: bool,
    max_width: Option<u16>,
    show_status: bool,
    theme: Option<Theme>,
}

impl PackListTable {
    /// Creates a new pack list table.
    #[must_use]
    pub fn new(rows: Vec<PackRow>) -> Self {
        Self {
            rows,
            style: TableStyle::default(),
            colors_enabled: true,
            max_width: None,
            show_status: true,
            theme: None,
        }
    }

    /// Sets the table style.
    #[must_use]
    pub fn with_style(mut self, style: TableStyle) -> Self {
        self.style = style;
        self
    }

    /// Configures from a theme.
    #[must_use]
    pub fn with_theme(mut self, theme: &Theme) -> Self {
        self.colors_enabled = theme.colors_enabled;
        self.style = theme.border_style.into();
        self.theme = Some(theme.clone());
        self
    }

    /// Sets maximum table width.
    #[must_use]
    pub fn with_max_width(mut self, width: u16) -> Self {
        self.max_width = Some(width);
        self
    }

    /// Hides the enabled/disabled status column.
    #[must_use]
    pub fn hide_status(mut self) -> Self {
        self.show_status = false;
        self
    }

    /// Renders the table to a string.
    #[must_use]
    pub fn render(&self) -> String {
        if self.rows.is_empty() {
            return String::from("No packs available.");
        }

        self.render_comfy()
    }

    /// Renders using comfy-table (default, or Markdown output).
    fn render_comfy(&self) -> String {
        let mut table = Table::new();
        self.style.apply_preset(&mut table);
        table.set_content_arrangement(ContentArrangement::Dynamic);

        if let Some(width) = self.max_width {
            table.set_width(width);
        }

        // Set header
        let mut header = vec!["Pack ID", "Name", "Destructive", "Safe"];
        if self.show_status {
            header.push("Status");
        }
        table.set_header(header);

        // Add rows
        for row in &self.rows {
            let mut cells = vec![
                Cell::new(&row.id),
                Cell::new(&row.name),
                Cell::new(row.destructive_count).set_alignment(CellAlignment::Right),
                Cell::new(row.safe_count).set_alignment(CellAlignment::Right),
            ];

            if self.show_status {
                cells.push(self.status_cell_comfy(row.enabled));
            }

            table.add_row(Row::from(cells));
        }

        table.to_string()
    }

    /// Creates a styled cell for enabled/disabled status (comfy-table version).
    fn status_cell_comfy(&self, enabled: bool) -> Cell {
        let (label, default_color) = if enabled {
            ("enabled", Color::Green)
        } else {
            ("disabled", Color::DarkGrey)
        };
        let color = self.theme.as_ref().map_or(default_color, |theme| {
            if enabled {
                to_table_color(theme.success_color)
            } else {
                to_table_color(theme.muted_color)
            }
        });

        let mut cell = Cell::new(label);
        if self.colors_enabled {
            cell = cell.fg(color);
        }
        cell
    }
}

/// Summary line formatter for table footers.
pub fn format_summary(total: usize, categories: &[(&str, usize)]) -> String {
    let parts: Vec<String> = categories
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(label, count)| format!("{count} {label}"))
        .collect();

    if parts.is_empty() {
        format!("{total} items")
    } else {
        format!("{total} items ({parts})", parts = parts.join(", "))
    }
}

fn truncate_with_ellipsis(text: &str, max_chars: usize) -> String {
    let text_len = text.chars().count();
    if text_len <= max_chars {
        return text.to_string();
    }

    if max_chars <= 3 {
        return text.chars().take(max_chars).collect();
    }

    let keep = max_chars.saturating_sub(3);
    let mut truncated: String = text.chars().take(keep).collect();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_results_table_empty() {
        let table = ScanResultsTable::new(vec![]);
        assert_eq!(table.render(), "No findings.");
    }

    #[test]
    fn test_scan_results_table_basic() {
        let rows = vec![
            ScanResultRow {
                file: "src/main.rs".to_string(),
                line: 42,
                severity: Severity::High,
                pattern_id: "core.git:reset-hard".to_string(),
                command_preview: None,
            },
            ScanResultRow {
                file: "Dockerfile".to_string(),
                line: 10,
                severity: Severity::Critical,
                pattern_id: "core.filesystem:rm-rf".to_string(),
                command_preview: None,
            },
        ];

        let table = ScanResultsTable::new(rows).with_style(TableStyle::Ascii);
        let output = table.render();

        assert!(output.contains("src/main.rs"));
        assert!(output.contains("42"));
        assert!(output.contains("HIGH"));
        assert!(output.contains("core.git:reset-hard"));
        assert!(output.contains("CRIT"));
    }

    #[test]
    fn test_scan_results_table_with_command_preview() {
        let rows = vec![ScanResultRow {
            file: "test.sh".to_string(),
            line: 1,
            severity: Severity::Medium,
            pattern_id: "core.git:clean".to_string(),
            command_preview: Some("git clean -fd".to_string()),
        }];

        let table = ScanResultsTable::new(rows)
            .with_style(TableStyle::Ascii)
            .with_command_preview();
        let output = table.render();

        assert!(output.contains("git clean -fd"));
        assert!(output.contains("Command"));
    }

    #[test]
    fn test_stats_table_empty() {
        let table = StatsTable::new(vec![]);
        assert_eq!(table.render(), "No statistics available.");
    }

    #[test]
    fn test_stats_table_basic() {
        let rows = vec![
            StatsRow {
                name: "core.git:reset-hard".to_string(),
                hits: 100,
                allowed: 10,
                denied: 90,
                noise_pct: Some(10.0),
            },
            StatsRow {
                name: "core.filesystem:rm-rf".to_string(),
                hits: 50,
                allowed: 25,
                denied: 25,
                noise_pct: Some(50.0),
            },
        ];

        let table = StatsTable::new(rows)
            .with_style(TableStyle::Ascii)
            .with_title("Pattern Statistics");
        let output = table.render();

        assert!(output.contains("Pattern Statistics"));
        assert!(output.contains("core.git:reset-hard"));
        assert!(output.contains("100"));
        assert!(output.contains("10.0%"));
        assert!(output.contains("50.0%"));
    }

    #[test]
    fn test_pack_list_table_empty() {
        let table = PackListTable::new(vec![]);
        assert_eq!(table.render(), "No packs available.");
    }

    #[test]
    fn test_pack_list_table_basic() {
        let rows = vec![
            PackRow {
                id: "core.git".to_string(),
                name: "Git Commands".to_string(),
                destructive_count: 8,
                safe_count: 15,
                enabled: true,
            },
            PackRow {
                id: "core.filesystem".to_string(),
                name: "Filesystem".to_string(),
                destructive_count: 5,
                safe_count: 10,
                enabled: false,
            },
        ];

        let table = PackListTable::new(rows).with_style(TableStyle::Ascii);
        let output = table.render();

        assert!(output.contains("core.git"));
        assert!(output.contains("Git Commands"));
        assert!(output.contains("enabled"));
        assert!(output.contains("disabled"));
    }

    #[test]
    fn test_pack_list_table_hide_status() {
        let rows = vec![PackRow {
            id: "core.git".to_string(),
            name: "Git Commands".to_string(),
            destructive_count: 8,
            safe_count: 15,
            enabled: true,
        }];

        let table = PackListTable::new(rows)
            .with_style(TableStyle::Ascii)
            .hide_status();
        let output = table.render();

        assert!(!output.contains("Status"));
        assert!(!output.contains("enabled"));
    }

    #[test]
    fn test_table_style_from_border_style() {
        assert_eq!(TableStyle::from(BorderStyle::Unicode), TableStyle::Unicode);
        assert_eq!(TableStyle::from(BorderStyle::Ascii), TableStyle::Ascii);
        assert_eq!(TableStyle::from(BorderStyle::None), TableStyle::Compact);
    }

    #[test]
    fn test_format_summary() {
        assert_eq!(format_summary(10, &[]), "10 items");
        assert_eq!(
            format_summary(10, &[("errors", 3), ("warnings", 7)]),
            "10 items (3 errors, 7 warnings)"
        );
        assert_eq!(
            format_summary(5, &[("errors", 0), ("warnings", 5)]),
            "5 items (5 warnings)"
        );
    }

    #[test]
    fn test_markdown_style() {
        let rows = vec![ScanResultRow {
            file: "test.sh".to_string(),
            line: 1,
            severity: Severity::Low,
            pattern_id: "test.pattern".to_string(),
            command_preview: None,
        }];

        let table = ScanResultsTable::new(rows).with_style(TableStyle::Markdown);
        let output = table.render();

        // Markdown tables use | as separators
        assert!(output.contains('|'));
        assert!(output.contains("test.sh"));
    }

    #[test]
    fn test_long_command_truncation() {
        let long_cmd =
            "git reset --hard HEAD~100 && rm -rf /very/long/path/that/should/be/truncated";
        let rows = vec![ScanResultRow {
            file: "test.sh".to_string(),
            line: 1,
            severity: Severity::Critical,
            pattern_id: "test".to_string(),
            command_preview: Some(long_cmd.to_string()),
        }];

        let table = ScanResultsTable::new(rows)
            .with_style(TableStyle::Ascii)
            .with_command_preview();
        // Use wide enough table to show our truncation
        let table = table.with_max_width(120);
        let output = table.render();

        // Should be truncated with ...
        assert!(
            output.contains("..."),
            "Output should contain ellipsis: {output}"
        );
        // Should not contain the full long command
        assert!(
            !output.contains("truncated"),
            "Output should not contain 'truncated': {output}"
        );
    }

    #[test]
    fn test_scan_results_with_theme() {
        let rows = vec![ScanResultRow {
            file: "test.rs".to_string(),
            line: 1,
            severity: Severity::Low,
            pattern_id: "test".to_string(),
            command_preview: None,
        }];

        let theme = Theme::no_color();
        let table = ScanResultsTable::new(rows).with_theme(&theme);
        let output = table.render();

        assert!(output.contains("test.rs"));
        assert!(output.contains("LOW"));
    }

    #[test]
    fn test_stats_table_with_theme() {
        let rows = vec![StatsRow {
            name: "test.rule".to_string(),
            hits: 50,
            allowed: 25,
            denied: 25,
            noise_pct: Some(50.0),
        }];

        let theme = Theme::no_color();
        let table = StatsTable::new(rows).with_theme(&theme);
        let output = table.render();

        assert!(output.contains("test.rule"));
        assert!(output.contains("50.0%"));
    }

    #[test]
    fn test_pack_list_with_theme() {
        let rows = vec![PackRow {
            id: "test.pack".to_string(),
            name: "Test Pack".to_string(),
            destructive_count: 5,
            safe_count: 10,
            enabled: true,
        }];

        let theme = Theme::no_color();
        let table = PackListTable::new(rows).with_theme(&theme);
        let output = table.render();

        assert!(output.contains("test.pack"));
        assert!(output.contains("enabled"));
    }

    #[test]
    fn test_scan_results_with_max_width() {
        let rows = vec![ScanResultRow {
            file: "very/long/path/to/some/file.rs".to_string(),
            line: 100,
            severity: Severity::Medium,
            pattern_id: "core.git.reset".to_string(),
            command_preview: None,
        }];

        let table = ScanResultsTable::new(rows)
            .with_style(TableStyle::Ascii)
            .with_max_width(60);
        let output = table.render();

        assert!(output.contains("File"));
        assert!(output.contains("MED"));
    }

    #[test]
    fn test_stats_table_nil_noise() {
        let rows = vec![StatsRow {
            name: "test.rule".to_string(),
            hits: 10,
            allowed: 5,
            denied: 5,
            noise_pct: None,
        }];

        let table = StatsTable::new(rows).with_style(TableStyle::Ascii);
        let output = table.render();

        assert!(output.contains('-')); // Nil noise should show dash
    }

    #[test]
    fn test_compact_table_style() {
        let rows = vec![ScanResultRow {
            file: "test.rs".to_string(),
            line: 1,
            severity: Severity::Low,
            pattern_id: "test".to_string(),
            command_preview: None,
        }];

        let table = ScanResultsTable::new(rows).with_style(TableStyle::Compact);
        let output = table.render();

        assert!(output.contains("test.rs"));
    }

    #[test]
    fn test_command_preview_missing() {
        let rows = vec![ScanResultRow {
            file: "test.rs".to_string(),
            line: 1,
            severity: Severity::Low,
            pattern_id: "test".to_string(),
            command_preview: None,
        }];

        let table = ScanResultsTable::new(rows)
            .with_style(TableStyle::Ascii)
            .with_command_preview();
        let output = table.render();

        // Missing command should show dash
        assert!(output.contains('-'));
    }

    #[test]
    fn test_markdown_uses_comfy_table() {
        // Markdown style always uses comfy-table (render_comfy).
        let rows = vec![ScanResultRow {
            file: "test.rs".to_string(),
            line: 1,
            severity: Severity::Low,
            pattern_id: "test".to_string(),
            command_preview: None,
        }];

        let table = ScanResultsTable::new(rows).with_style(TableStyle::Markdown);
        let output = table.render();

        // Markdown tables use | as column separators
        assert!(
            output.contains('|'),
            "Markdown output should use pipe separators: {output}"
        );
        // Should not contain ANSI escape codes or rich markup
        assert!(
            !output.contains('\x1b'),
            "Markdown should not contain ANSI escapes: {output}"
        );
    }

    #[test]
    fn test_truncate_with_ellipsis_short_string() {
        assert_eq!(truncate_with_ellipsis("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_with_ellipsis_exact_length() {
        assert_eq!(truncate_with_ellipsis("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_with_ellipsis_needs_truncation() {
        let result = truncate_with_ellipsis("hello world", 8);
        assert_eq!(result.chars().count(), 8);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_with_ellipsis_very_short_max() {
        // max_chars <= 3, no ellipsis, just truncate
        let result = truncate_with_ellipsis("hello", 2);
        assert_eq!(result, "he");
    }

    #[test]
    fn test_truncate_with_ellipsis_max_three() {
        let result = truncate_with_ellipsis("hello", 3);
        assert_eq!(result, "hel");
    }

    #[test]
    fn test_truncate_with_ellipsis_empty() {
        assert_eq!(truncate_with_ellipsis("", 5), "");
    }

    #[test]
    fn test_table_style_is_markdown() {
        assert!(TableStyle::Markdown.is_markdown());
        assert!(!TableStyle::Unicode.is_markdown());
        assert!(!TableStyle::Ascii.is_markdown());
        assert!(!TableStyle::Compact.is_markdown());
    }

    #[test]
    fn test_table_style_default() {
        assert_eq!(TableStyle::default(), TableStyle::Unicode);
    }

    #[test]
    fn test_severity_label() {
        assert_eq!(severity_label(Severity::Critical), "CRIT");
        assert_eq!(severity_label(Severity::High), "HIGH");
        assert_eq!(severity_label(Severity::Medium), "MED");
        assert_eq!(severity_label(Severity::Low), "LOW");
    }

    #[test]
    fn test_stats_table_high_noise() {
        let rows = vec![StatsRow {
            name: "noisy.rule".to_string(),
            hits: 100,
            allowed: 90,
            denied: 10,
            noise_pct: Some(90.0),
        }];

        let table = StatsTable::new(rows).with_style(TableStyle::Ascii);
        let output = table.render();
        assert!(output.contains("90.0%"));
    }

    #[test]
    fn test_stats_table_with_title_and_width() {
        let rows = vec![StatsRow {
            name: "rule".to_string(),
            hits: 10,
            allowed: 5,
            denied: 5,
            noise_pct: Some(50.0),
        }];

        let table = StatsTable::new(rows)
            .with_style(TableStyle::Ascii)
            .with_title("Statistics Report")
            .with_max_width(80);
        let output = table.render();
        assert!(output.starts_with("Statistics Report"));
    }

    #[test]
    fn test_scan_results_colors_disabled() {
        let rows = vec![ScanResultRow {
            file: "test.rs".to_string(),
            line: 1,
            severity: Severity::Critical,
            pattern_id: "test".to_string(),
            command_preview: None,
        }];

        let mut table = ScanResultsTable::new(rows).with_style(TableStyle::Ascii);
        table.colors_enabled = false;
        let output = table.render();
        // Should render without ANSI codes
        assert!(!output.contains('\x1b'));
        assert!(output.contains("CRIT"));
    }
}
