//! Hook protocol handling.
//!
//! This module handles JSON input/output for supported hook protocols
//! (Claude Code, Copilot, and Gemini). It parses incoming hook requests
//! and formats denial responses.

use crate::evaluator::MatchSpan;
use crate::highlight::HighlightSpan;
use crate::output::auto_theme;
#[cfg(feature = "rich-output")]
use crate::output::console::console;
use crate::output::denial::DenialBox;
use crate::output::theme::Severity as ThemeSeverity;
use crate::packs::PatternSuggestion;
use colored::Colorize;
#[cfg(feature = "rich-output")]
#[allow(unused_imports)]
use rich_rust::prelude::*;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::io::{self, IsTerminal, Read, Write};
use std::time::Duration;

/// Input structure from supported hook protocols.
#[derive(Debug, Deserialize)]
pub struct HookInput {
    /// Hook event name (used by some clients, e.g. Copilot CLI: "pre-tool-use").
    pub event: Option<String>,

    /// Gemini hook event name (e.g., "BeforeTool").
    #[serde(alias = "hookEventName")]
    pub hook_event_name: Option<String>,

    /// Session id. Claude Code sends this on every `PreToolUse`; Gemini sends
    /// it too. Read for presence only, in `detect_protocol`.
    ///
    /// Calling these three "Gemini" fields is what caused `.agent-config-d5c7l`:
    /// they were treated as a marker for Gemini, so a real Claude payload took
    /// the Gemini branch and got an answer Claude Code cannot parse.
    /// `hook_event_name` is the field that actually distinguishes the clients.
    pub session_id: Option<String>,

    /// Transcript path. Sent by Claude Code and Gemini alike; never opened.
    pub transcript_path: Option<String>,

    /// The directory the agent is running in. Sent by Claude Code and Gemini
    /// alike. Read for presence only; dcg uses its own process cwd for scope.
    pub cwd: Option<String>,

    /// Gemini event timestamp.
    pub timestamp: Option<String>,

    /// The name of the tool being invoked (e.g., "Bash", "Read", "Write").
    #[serde(alias = "toolName")]
    pub tool_name: Option<String>,

    /// Tool-specific input parameters.
    #[serde(alias = "toolInput")]
    pub tool_input: Option<ToolInput>,

    /// Alternate tool arguments format used by some clients.
    /// May be a JSON string (e.g. "{\"command\":\"...\"}") or an object.
    #[serde(alias = "toolArgs")]
    pub tool_args: Option<serde_json::Value>,
}

/// Tool-specific input containing the command to execute.
#[derive(Debug, Deserialize)]
pub struct ToolInput {
    /// The command string (for Bash tools).
    pub command: Option<serde_json::Value>,
}

/// Output structure for denying a command.
#[derive(Debug, Serialize)]
pub struct HookOutput<'a> {
    /// Hook-specific output with the decision.
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput<'a>,
}

/// Hook-specific output with decision and reason.
#[derive(Debug, Serialize)]
pub struct HookSpecificOutput<'a> {
    /// Always "`PreToolUse`" for this hook.
    #[serde(rename = "hookEventName")]
    pub hook_event_name: &'static str,

    /// The permission decision: "allow" or "deny".
    #[serde(rename = "permissionDecision")]
    pub permission_decision: &'static str,

    /// Human-readable explanation of the decision.
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: Cow<'a, str>,

    /// Short allow-once code (if a pending exception was recorded).
    #[serde(rename = "allowOnceCode", skip_serializing_if = "Option::is_none")]
    pub allow_once_code: Option<String>,

    /// Full hash for allow-once disambiguation (if available).
    #[serde(rename = "allowOnceFullHash", skip_serializing_if = "Option::is_none")]
    pub allow_once_full_hash: Option<String>,

    // --- New fields for AI agent ergonomics (git_safety_guard-e4fl.1) ---
    /// Stable rule identifier (e.g., "core.git:reset-hard").
    /// Format: "{packId}:{patternName}"
    #[serde(rename = "ruleId", skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,

    /// Pack identifier that matched (e.g., "core.git").
    #[serde(rename = "packId", skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,

    /// Severity level of the matched pattern.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<crate::packs::Severity>,

    /// Confidence score for this match (0.0-1.0).
    /// Higher values indicate higher confidence that this is a true positive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,

    /// Remediation suggestions for the blocked command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
}

/// Copilot-compatible denial output for pre-tool-use hooks.
///
/// Copilot hooks can consume either:
/// - `continue=false` with `stopReason`
/// - `permissionDecision=deny` with `permissionDecisionReason`
///
/// We emit both for compatibility across documented variants.
#[derive(Debug, Serialize)]
pub struct CopilotHookOutput<'a> {
    /// Whether execution should continue.
    #[serde(rename = "continue")]
    pub continue_execution: bool,

    /// Human-readable stop reason.
    #[serde(rename = "stopReason")]
    pub stop_reason: Cow<'a, str>,

    /// Permission decision (`deny`).
    #[serde(rename = "permissionDecision")]
    pub permission_decision: &'static str,

    /// Human-readable explanation of the decision.
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: Cow<'a, str>,

    /// Short allow-once code (if a pending exception was recorded).
    #[serde(rename = "allowOnceCode", skip_serializing_if = "Option::is_none")]
    pub allow_once_code: Option<String>,

    /// Full hash for allow-once disambiguation (if available).
    #[serde(rename = "allowOnceFullHash", skip_serializing_if = "Option::is_none")]
    pub allow_once_full_hash: Option<String>,

    /// Stable rule identifier (e.g., "core.git:reset-hard").
    #[serde(rename = "ruleId", skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,

    /// Pack identifier that matched (e.g., "core.git").
    #[serde(rename = "packId", skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,

    /// Severity level of the matched pattern.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<crate::packs::Severity>,

    /// Confidence score for this match (0.0-1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,

    /// Remediation suggestions for the blocked command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
}

/// Gemini-compatible denial output for `BeforeTool` hooks.
#[derive(Debug, Serialize)]
pub struct GeminiHookOutput<'a> {
    /// Decision for this hook event.
    pub decision: &'static str,

    /// Why the action was denied.
    pub reason: Cow<'a, str>,

    /// Human-visible message in Gemini CLI.
    #[serde(rename = "systemMessage", skip_serializing_if = "Option::is_none")]
    pub system_message: Option<Cow<'a, str>>,

    /// Short allow-once code (if a pending exception was recorded).
    #[serde(rename = "allowOnceCode", skip_serializing_if = "Option::is_none")]
    pub allow_once_code: Option<String>,

    /// Full hash for allow-once disambiguation (if available).
    #[serde(rename = "allowOnceFullHash", skip_serializing_if = "Option::is_none")]
    pub allow_once_full_hash: Option<String>,

    /// Stable rule identifier (e.g., "core.git:reset-hard").
    #[serde(rename = "ruleId", skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,

    /// Pack identifier that matched (e.g., "core.git").
    #[serde(rename = "packId", skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,

    /// Severity level of the matched pattern.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<crate::packs::Severity>,

    /// Confidence score for this match (0.0-1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,

    /// Remediation suggestions for the blocked command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
}

/// Hook protocol variant for response formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookProtocol {
    /// Claude Code / Augment-compatible `hookSpecificOutput` protocol.
    ClaudeCompatible,
    /// Copilot hook protocol (`continue` / `stopReason` + permission fields).
    Copilot,
    /// Gemini hook protocol (`decision` / `reason`).
    Gemini,
}

/// Allow-once metadata for denial output.
#[derive(Debug, Clone)]
pub struct AllowOnceInfo {
    pub code: String,
    pub full_hash: String,
}

/// Remediation suggestions for blocked commands.
///
/// Provides actionable alternatives and context for users to safely
/// accomplish their intended goal.
#[derive(Debug, Clone, Serialize)]
pub struct Remediation {
    /// A safe alternative command that accomplishes a similar goal.
    #[serde(rename = "safeAlternative", skip_serializing_if = "Option::is_none")]
    pub safe_alternative: Option<String>,

    /// Detailed explanation of why the command was blocked and what to do instead.
    pub explanation: String,

    /// The command to run to allow this specific command once (e.g., "dcg allow-once abc12").
    #[serde(rename = "allowOnceCommand")]
    pub allow_once_command: String,
}

/// Result of processing a hook request.
#[derive(Debug)]
pub enum HookResult {
    /// Command is allowed (no output needed).
    Allow,

    /// Command is denied with a reason.
    Deny {
        /// The original command that was blocked.
        command: String,
        /// Why the command was blocked.
        reason: String,
        /// Which pack blocked it (optional).
        pack: Option<String>,
        /// Which pattern matched (optional).
        pattern_name: Option<String>,
    },

    /// Not a Bash command, skip processing.
    Skip,

    /// Error parsing input.
    ParseError,
}

/// Error type for reading and parsing hook input.
#[derive(Debug)]
pub enum HookReadError {
    /// Failed to read from stdin.
    Io(io::Error),
    /// Input exceeded the configured size limit.
    InputTooLarge(usize),
    /// Failed to parse JSON input.
    Json(serde_json::Error),
}

/// Read and parse hook input from stdin.
///
/// # Errors
///
/// Returns [`HookReadError::Io`] if stdin cannot be read, [`HookReadError::Json`]
/// if the input is not valid hook JSON, or [`HookReadError::InputTooLarge`] if
/// the input exceeds `max_bytes`.
pub fn read_hook_input(max_bytes: usize) -> Result<HookInput, HookReadError> {
    let mut input = String::with_capacity(256);
    {
        let stdin = io::stdin();
        // Read up to limit + 1 to detect overflow
        let mut handle = stdin.lock().take(max_bytes as u64 + 1);
        handle
            .read_to_string(&mut input)
            .map_err(HookReadError::Io)?;
    }

    if input.len() > max_bytes {
        return Err(HookReadError::InputTooLarge(input.len()));
    }

    serde_json::from_str(&input).map_err(HookReadError::Json)
}

/// Detect which hook protocol should be used for output formatting.
#[must_use]
pub fn detect_protocol(input: &HookInput) -> HookProtocol {
    let tool_name = input
        .tool_name
        .as_deref()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let hook_event_name = input.hook_event_name.as_deref().unwrap_or_default();
    let has_gemini_context = input.session_id.is_some()
        || input.transcript_path.is_some()
        || input.cwd.is_some()
        || input.timestamp.is_some();
    let has_gemini_before_tool_marker = hook_event_name.eq_ignore_ascii_case("beforetool")
        && matches!(
            tool_name.as_str(),
            "run_shell_command" | "run-shell-command"
        );

    // Claude Code sends session_id, transcript_path AND cwd on every PreToolUse
    // invocation, so `has_gemini_context` below is true for every real Claude
    // payload — and it was tested first, so dcg answered Claude Code in Gemini's
    // shape. Claude Code reads hookSpecificOutput.permissionDecision and ignores
    // {"decision": ...}, so a denial it could not parse became an effective
    // ALLOW. Measured 2026-09-02: against this binary the guard-liveness suite
    // saw all three of its deny cases come back "allow" while dcg was in fact
    // denying all three internally — the verdict was right and unreadable.
    //
    // hook_event_name is the unambiguous marker. Claude sends PascalCase event
    // names ("PreToolUse"); Gemini sends "BeforeTool".
    if hook_event_name.eq_ignore_ascii_case("PreToolUse") {
        return HookProtocol::ClaudeCompatible;
    }

    // Gemini hooks usually include session envelope fields, but some integrations
    // only provide the event marker + tool payload.
    if has_gemini_context || has_gemini_before_tool_marker {
        HookProtocol::Gemini
    } else if input.event.is_some()
        || input.tool_args.is_some()
        || matches!(
            tool_name.as_str(),
            "run_shell_command" | "run-shell-command"
        )
    {
        HookProtocol::Copilot
    } else {
        HookProtocol::ClaudeCompatible
    }
}

fn is_supported_shell_tool(tool_name: Option<&str>) -> bool {
    let Some(tool_name) = tool_name else {
        return false;
    };

    matches!(
        tool_name.to_ascii_lowercase().as_str(),
        "bash" | "launch-process" | "run_shell_command" | "run-shell-command"
    )
}

fn extract_command_from_tool_args(tool_args: &serde_json::Value) -> Option<String> {
    match tool_args {
        serde_json::Value::Object(map) => map.get("command").and_then(|v| match v {
            serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }),
        serde_json::Value::String(s) => {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
                extract_command_from_tool_args(&parsed)
            } else if s.is_empty() {
                None
            } else {
                Some(s.clone())
            }
        }
        _ => None,
    }
}

/// Extract command and protocol from hook input.
#[must_use]
pub fn extract_command_with_protocol(input: &HookInput) -> Option<(String, HookProtocol)> {
    // Only process shell-command invocations for supported clients.
    if !is_supported_shell_tool(input.tool_name.as_deref()) {
        return None;
    }

    let protocol = detect_protocol(input);

    if let Some(tool_input) = input.tool_input.as_ref() {
        if let Some(serde_json::Value::String(s)) = tool_input.command.as_ref() {
            if !s.is_empty() {
                return Some((s.clone(), protocol));
            }
        }
    }

    if let Some(tool_args) = input.tool_args.as_ref() {
        if let Some(command) = extract_command_from_tool_args(tool_args) {
            return Some((command, protocol));
        }
    }

    None
}

/// Extract the command string from hook input.
#[must_use]
pub fn extract_command(input: &HookInput) -> Option<String> {
    extract_command_with_protocol(input).map(|(command, _)| command)
}

/// Configure colored output based on TTY detection.
pub fn configure_colors() {
    if std::env::var_os("NO_COLOR").is_some() || std::env::var_os("DCG_NO_COLOR").is_some() {
        colored::control::set_override(false);
        return;
    }

    if !io::stderr().is_terminal() {
        colored::control::set_override(false);
    }
}

/// Format the explain hint line for copy-paste convenience.
fn format_explain_hint(command: &str) -> String {
    // Escape double quotes in command for safe copy-paste
    let escaped = command.replace('"', "\\\"");
    format!("Tip: dcg explain \"{escaped}\"")
}

fn build_rule_id(pack: Option<&str>, pattern: Option<&str>) -> Option<String> {
    match (pack, pattern) {
        (Some(pack_id), Some(pattern_name)) => Some(format!("{pack_id}:{pattern_name}")),
        _ => None,
    }
}

fn format_explanation_text(
    explanation: Option<&str>,
    rule_id: Option<&str>,
    pack: Option<&str>,
) -> String {
    let trimmed = explanation.map(str::trim).filter(|text| !text.is_empty());

    if let Some(text) = trimmed {
        return text.to_string();
    }

    if let Some(rule) = rule_id {
        return format!(
            "Matched destructive pattern {rule}. No additional explanation is available yet. See pack documentation for details."
        );
    }

    if let Some(pack_name) = pack {
        return format!(
            "Matched destructive pack {pack_name}. No additional explanation is available yet. See pack documentation for details."
        );
    }

    "Matched a destructive pattern. No additional explanation is available yet. See pack documentation for details."
        .to_string()
}

fn format_explanation_block(explanation: &str) -> String {
    let mut lines = explanation.lines();
    let Some(first) = lines.next() else {
        return "Explanation:".to_string();
    };

    let mut output = format!("Explanation: {first}");
    for line in lines {
        output.push('\n');
        output.push_str("             ");
        output.push_str(line);
    }
    output
}

/// Format the denial message for the JSON output (plain text).
#[must_use]
pub fn format_denial_message(
    command: &str,
    reason: &str,
    explanation: Option<&str>,
    pack: Option<&str>,
    pattern: Option<&str>,
    allow_once_code: Option<&str>,
) -> String {
    let explain_hint = format_explain_hint(command);
    let rule_id = build_rule_id(pack, pattern);
    let explanation_text = format_explanation_text(explanation, rule_id.as_deref(), pack);
    let explanation_block = format_explanation_block(&explanation_text);

    let rule_line = rule_id.as_deref().map_or_else(
        || {
            pack.map(|pack_name| format!("Pack: {pack_name}\n\n"))
                .unwrap_or_default()
        },
        |rule| format!("Rule: {rule}\n\n"),
    );

    // The escape hatch has to be in THIS string. A denial already carries the
    // code in `allowOnceCode` and in `remediation.allowOnceCommand`, and the
    // stderr box prints it too — but a client that shows its agent only
    // `permissionDecisionReason`, and does not surface PreToolUse stderr, leaves
    // that agent with no code to quote. Measured 2026-09-03 under
    // `.agent-config-a6jka`: an agent hit a false positive in exactly that
    // situation. A hatch the caller cannot see is a hatch that does not open,
    // and what it reaches for instead is rewriting the command until the guard
    // stops matching — worse than an allow-once, because an allow-once is
    // recorded, scoped and expiring and an evasion is none of those.
    //
    // The runnable command matches `output::denial`; the sentence introducing it
    // deliberately does not, because this reader cannot see the box that the
    // "To allow once:" label sits in.
    //
    // An empty code is treated as no code. `dcg allow-once ` with nothing after
    // it is not a runnable command, and it would render byte-identical to a real
    // code under the golden mask — so the guards would go on passing while the
    // hatch line said nothing usable.
    let allow_once_line = allow_once_code
        .filter(|code| !code.is_empty())
        .map_or_else(String::new, |code| {
            format!("If this is a false positive: dcg allow-once {code}\n\n")
        });

    // The command appears ONCE, inside the `Tip:` line. It used to appear twice —
    // here and in a bare `Command: {command}` line — so this string grew as
    // 2*len(command) + K. A PreToolUse decision is replayed in the agent
    // transcript on every later turn of that session, so the second echo was
    // paid per turn and carried no information the caller lacked: it just wrote
    // the command. Measured over a 38-day corpus (569 blocks) that echo was
    // ~29% of dcg's whole transcript cost. Keeping the `Tip:` copy rather than
    // the bare `Command:` line preserves the one form that is also runnable.
    // Upstream made the same choice in 44f4d43 (Dicklesworthstone#299); this
    // fork predates that commit, so it is applied here in the same shape to
    // keep the two trees rebasable. Guarded by
    // `denial_message_echoes_command_once`.
    format!(
        "BLOCKED by dcg\n\n\
         {explain_hint}\n\n\
         Reason: {reason}\n\n\
         {explanation_block}\n\n\
         {rule_line}\
         {allow_once_line}\
         If this operation is truly needed, ask the user for explicit \
         permission and have them run the command manually."
    )
}

/// Convert packs::Severity to theme::Severity
fn to_output_severity(s: crate::packs::Severity) -> ThemeSeverity {
    match s {
        crate::packs::Severity::Critical => ThemeSeverity::Critical,
        crate::packs::Severity::High => ThemeSeverity::High,
        crate::packs::Severity::Medium => ThemeSeverity::Medium,
        crate::packs::Severity::Low => ThemeSeverity::Low,
    }
}

const MAX_SUGGESTIONS: usize = 4;

/// Print a colorful warning to stderr for human visibility.
#[allow(clippy::too_many_lines)]
pub fn print_colorful_warning(
    command: &str,
    _reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
    allow_once_code: Option<&str>,
    matched_span: Option<&MatchSpan>,
    pattern_suggestions: &[PatternSuggestion],
    severity: Option<crate::packs::Severity>,
) {
    #[cfg(feature = "rich-output")]
    let console_instance = console();
    let theme = auto_theme();

    // Prepare content for DenialBox
    let rule_id = build_rule_id(pack, pattern);
    let pattern_display = rule_id.as_deref().or(pack).unwrap_or("unknown pattern");

    let theme_severity = severity
        .map(to_output_severity)
        .unwrap_or(ThemeSeverity::High);

    let explanation_text = explanation.map(str::trim).filter(|text| !text.is_empty());

    // Create span for highlighting
    let span = matched_span
        .map(|s| HighlightSpan::new(s.start, s.end))
        .unwrap_or_else(|| HighlightSpan::new(0, 0)); // Fallback

    let suggestions_enabled = crate::output::suggestions_enabled();

    // Convert suggestions to alternatives (platform-filtered, capped)
    let filtered_suggestions: Vec<&PatternSuggestion> = if suggestions_enabled {
        pattern_suggestions
            .iter()
            .filter(|s| s.platform.matches_current())
            .collect()
    } else {
        Vec::new()
    };
    let mut alternatives: Vec<String> = filtered_suggestions
        .iter()
        .take(MAX_SUGGESTIONS)
        .map(|s| format!("{}: {}", s.description, s.command))
        .collect();

    // Add contextual suggestion if available and no pattern suggestions
    if suggestions_enabled && alternatives.is_empty() {
        if let Some(sugg) = get_contextual_suggestion(command) {
            alternatives.push(sugg.to_string());
        }
    }

    let mut denial = DenialBox::new(command, span, pattern_display, theme_severity)
        .with_alternatives(alternatives);

    if let Some(text) = explanation_text {
        denial = denial.with_explanation(text);
    }

    if let Some(code) = allow_once_code {
        denial = denial.with_allow_once_code(code);
    }

    // Render the denial box
    // Note: DcgConsole auto-detects stderr usage
    eprintln!("{}", denial.render(&theme));

    // Secondary info (Legacy: printed after box; Rich: could use panels)
    #[cfg(feature = "rich-output")]
    if !console_instance.is_plain() {
        // In rich mode, we might want additional panels or info
        // For now, let's keep it simple as DenialBox handles most things
        // But we might want to print the "Learn more" links
    }

    // "Learn more" section (common to both modes, usually printed after the main warning)
    let escaped_cmd = command.replace('"', "\\\"");
    let truncated_cmd = truncate_for_display(&escaped_cmd, 45);
    let explain_cmd = format!("dcg explain \"{truncated_cmd}\"");

    // Let's print the footer links
    let footer_style = if theme.colors_enabled { "\x1b[90m" } else { "" }; // Bright black
    let reset = if theme.colors_enabled { "\x1b[0m" } else { "" };
    let cyan = if theme.colors_enabled { "\x1b[36m" } else { "" };

    eprintln!("{footer_style}Learn more:{reset}");
    eprintln!("  $ {cyan}{explain_cmd}{reset}");

    if let Some(ref rule) = rule_id {
        eprintln!("  $ {cyan}dcg allowlist add {rule} --project{reset}");
    }

    eprintln!();
    eprintln!("{footer_style}False positive? File an issue:{reset}");
    eprintln!(
        "{footer_style}https://github.com/Dicklesworthstone/destructive_command_guard/issues/new?template=false_positive.yml{reset}"
    );
    eprintln!();
}

#[cfg(feature = "rich-output")]
#[allow(dead_code)] // TODO: Integrate into rich output path
fn render_suggestions_panel(suggestions: &[PatternSuggestion]) -> String {
    use rich_rust::r#box::ROUNDED;
    use rich_rust::prelude::*;

    // Build content as a Vec of lines, then join
    let mut lines = Vec::new();
    if !crate::output::suggestions_enabled() {
        return String::new();
    }

    let filtered: Vec<&PatternSuggestion> = suggestions
        .iter()
        .filter(|s| s.platform.matches_current())
        .take(MAX_SUGGESTIONS)
        .collect();

    for (i, s) in filtered.iter().enumerate() {
        lines.push(format!("[bold cyan]{}.[/] {}", i + 1, s.description));
        lines.push(format!("   [green]$[/] [cyan]{}[/]", s.command));
    }
    let content_str = lines.join("\n");

    let width = crate::output::terminal_width() as usize;
    Panel::from_text(&content_str)
        .title("[yellow bold] 💡 Suggestions [/]")
        .box_style(&ROUNDED)
        .border_style(Style::new().color(Color::parse("yellow").unwrap_or_default()))
        .render_plain(width)
}

/// Truncate a string for display, appending "..." if truncated.
fn truncate_for_display(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Find a safe UTF-8 boundary for truncation
        let target = max_len.saturating_sub(3);
        let boundary = s
            .char_indices()
            .take_while(|(i, _)| *i < target)
            .last()
            .map_or(0, |(i, c)| i + c.len_utf8());
        format!("{}...", &s[..boundary])
    }
}

/// Get context-specific suggestion based on the blocked command.
fn get_contextual_suggestion(command: &str) -> Option<&'static str> {
    if command.contains("reset") || command.contains("checkout") {
        Some("Consider using 'git stash' first to save your changes.")
    } else if command.contains("clean") {
        Some("Use 'git clean -n' first to preview what would be deleted.")
    } else if command.contains("push") && command.contains("force") {
        Some("Consider using '--force-with-lease' for safer force pushing.")
    } else if command.contains("rm -rf") || command.contains("rm -r") {
        Some("Verify the path carefully before running rm -rf manually.")
    } else if command.contains("DROP") || command.contains("drop") {
        Some("Consider backing up the database/table before dropping.")
    } else if command.contains("kubectl") && command.contains("delete") {
        Some("Use 'kubectl delete --dry-run=client' to preview changes first.")
    } else if command.contains("docker") && command.contains("prune") {
        Some("Use 'docker system df' to see what would be affected.")
    } else if command.contains("terraform") && command.contains("destroy") {
        Some("Use 'terraform plan -destroy' to preview changes first.")
    } else {
        None
    }
}

/// Output a denial response to stdout (JSON for hook protocol).
///
/// `allow_once_suffices` says whether a bare `dcg allow-once <code>` would
/// actually clear THIS denial. It is false for a config blocklist entry, which
/// needs `--force` on top and is the user's own explicit decision rather than a
/// pattern that might be a false positive. The caller states it because the
/// caller holds the denial's `MatchSource`; the formatter would otherwise have
/// to infer it from `pack`/`pattern` both being `None`, which is true of a
/// config denial today by coincidence rather than by contract.
///
/// It gates only the prose. The machine-readable `allowOnceCode` and
/// `remediation` still carry the code, because the code is real and `--force`
/// can still redeem it — what must not happen is the guard printing a
/// suggestion in its own voice that returns an error when run.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn output_denial_for_protocol(
    protocol: HookProtocol,
    command: &str,
    reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
    allow_once: Option<&AllowOnceInfo>,
    matched_span: Option<&MatchSpan>,
    severity: Option<crate::packs::Severity>,
    confidence: Option<f64>,
    pattern_suggestions: &[PatternSuggestion],
    allow_once_suffices: bool,
) {
    // Print colorful warning to stderr (visible to user)
    let allow_once_code = allow_once.map(|info| info.code.as_str());
    print_colorful_warning(
        command,
        reason,
        pack,
        pattern,
        explanation,
        allow_once_code,
        matched_span,
        pattern_suggestions,
        severity,
    );

    // Build JSON response for hook protocol (stdout)
    let hatch_code = if allow_once_suffices {
        allow_once_code
    } else {
        None
    };
    let message = format_denial_message(command, reason, explanation, pack, pattern, hatch_code);
    let rule_id = build_rule_id(pack, pattern);
    let remediation = allow_once.map(|info| {
        let explanation_text = format_explanation_text(explanation, rule_id.as_deref(), pack);
        Remediation {
            safe_alternative: get_contextual_suggestion(command).map(String::from),
            explanation: explanation_text,
            allow_once_command: format!("dcg allow-once {}", info.code),
        }
    });

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    match protocol {
        HookProtocol::ClaudeCompatible => {
            let output = HookOutput {
                hook_specific_output: HookSpecificOutput {
                    hook_event_name: "PreToolUse",
                    permission_decision: "deny",
                    permission_decision_reason: Cow::Owned(message.clone()),
                    allow_once_code: allow_once.map(|info| info.code.clone()),
                    allow_once_full_hash: allow_once.map(|info| info.full_hash.clone()),
                    rule_id,
                    pack_id: pack.map(String::from),
                    severity,
                    confidence,
                    remediation,
                },
            };

            let _ = serde_json::to_writer(&mut handle, &output);
            let _ = writeln!(handle);
        }
        HookProtocol::Copilot => {
            let output = CopilotHookOutput {
                continue_execution: false,
                stop_reason: Cow::Owned(format!("BLOCKED by dcg: {reason}")),
                permission_decision: "deny",
                permission_decision_reason: Cow::Owned(message.clone()),
                allow_once_code: allow_once.map(|info| info.code.clone()),
                allow_once_full_hash: allow_once.map(|info| info.full_hash.clone()),
                rule_id,
                pack_id: pack.map(String::from),
                severity,
                confidence,
                remediation,
            };

            let _ = serde_json::to_writer(&mut handle, &output);
            let _ = writeln!(handle);
        }
        HookProtocol::Gemini => {
            let output = GeminiHookOutput {
                decision: "deny",
                reason: Cow::Owned(message),
                system_message: Some(Cow::Owned(format!("BLOCKED by dcg: {reason}"))),
                allow_once_code: allow_once.map(|info| info.code.clone()),
                allow_once_full_hash: allow_once.map(|info| info.full_hash.clone()),
                rule_id,
                pack_id: pack.map(String::from),
                severity,
                confidence,
                remediation,
            };

            let _ = serde_json::to_writer(&mut handle, &output);
            let _ = writeln!(handle);
        }
    }
}

/// Output a denial response to stdout (JSON for hook protocol).
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn output_denial(
    command: &str,
    reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
    allow_once: Option<&AllowOnceInfo>,
    matched_span: Option<&MatchSpan>,
    severity: Option<crate::packs::Severity>,
    confidence: Option<f64>,
    pattern_suggestions: &[PatternSuggestion],
    allow_once_suffices: bool,
) {
    output_denial_for_protocol(
        HookProtocol::ClaudeCompatible,
        command,
        reason,
        pack,
        pattern,
        explanation,
        allow_once,
        matched_span,
        severity,
        confidence,
        pattern_suggestions,
        allow_once_suffices,
    );
}

/// Output a warning to stderr (no JSON deny; command is allowed).
#[cold]
#[inline(never)]
pub fn output_warning(
    command: &str,
    reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();

    let _ = writeln!(handle);
    let _ = writeln!(
        handle,
        "{} {}",
        "dcg WARNING (allowed by policy):".yellow().bold(),
        reason
    );

    // Build rule_id from pack and pattern
    let rule_id = build_rule_id(pack, pattern);
    let explanation_text = format_explanation_text(explanation, rule_id.as_deref(), pack);
    let mut explanation_lines = explanation_text.lines();

    if let Some(first) = explanation_lines.next() {
        let _ = writeln!(handle, "  {} {}", "Explanation:".bright_black(), first);
        for line in explanation_lines {
            let _ = writeln!(handle, "               {line}");
        }
    }

    if let Some(ref rule) = rule_id {
        let _ = writeln!(handle, "  {} {}", "Rule:".bright_black(), rule);
    } else if let Some(pack_name) = pack {
        let _ = writeln!(handle, "  {} {}", "Pack:".bright_black(), pack_name);
    }

    let _ = writeln!(handle, "  {} {}", "Command:".bright_black(), command);
    let _ = writeln!(
        handle,
        "  {}",
        "No hook JSON deny was emitted; this warning is informational.".bright_black()
    );
}

/// Log a blocked command to a file (if logging is enabled).
///
/// # Errors
///
/// Returns any I/O errors encountered while creating directories or appending
/// to the log file.
pub fn log_blocked_command(
    log_file: &str,
    command: &str,
    reason: &str,
    pack: Option<&str>,
) -> io::Result<()> {
    use std::fs::OpenOptions;

    // Expand ~ in path
    let path = if log_file.starts_with("~/") {
        dirs::home_dir().map_or_else(
            || std::path::PathBuf::from(log_file),
            |h| h.join(&log_file[2..]),
        )
    } else {
        std::path::PathBuf::from(log_file)
    };

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    let timestamp = chrono_lite_timestamp();
    let pack_str = pack.unwrap_or("unknown");

    writeln!(file, "[{timestamp}] [{pack_str}] {reason}")?;
    writeln!(file, "  Command: {command}")?;
    writeln!(file)?;

    Ok(())
}

/// Log a budget skip to a file (if logging is enabled).
///
/// # Errors
///
/// Returns any I/O errors encountered while creating directories or appending
/// to the log file.
pub fn log_budget_skip(
    log_file: &str,
    command: &str,
    stage: &str,
    elapsed: Duration,
    budget: Duration,
) -> io::Result<()> {
    use std::fs::OpenOptions;

    // Expand ~ in path
    let path = if log_file.starts_with("~/") {
        dirs::home_dir().map_or_else(
            || std::path::PathBuf::from(log_file),
            |h| h.join(&log_file[2..]),
        )
    } else {
        std::path::PathBuf::from(log_file)
    };

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    let timestamp = chrono_lite_timestamp();
    writeln!(
        file,
        "[{timestamp}] [budget] evaluation skipped due to budget at {stage}"
    )?;
    writeln!(
        file,
        "  Budget: {}ms, Elapsed: {}ms",
        budget.as_millis(),
        elapsed.as_millis()
    )?;
    writeln!(file, "  Command: {command}")?;
    writeln!(file)?;

    Ok(())
}

/// Simple timestamp without chrono dependency.
/// Returns Unix epoch seconds as a string (e.g., "1704672000").
fn chrono_lite_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            // SAFETY: We hold ENV_LOCK during all tests that use this guard,
            // ensuring no concurrent access to environment variables.
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }

        #[allow(dead_code)]
        fn remove(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            // SAFETY: We hold ENV_LOCK during all tests that use this guard,
            // ensuring no concurrent access to environment variables.
            unsafe { std::env::remove_var(key) };
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                // SAFETY: We hold ENV_LOCK during all tests that use this guard,
                // ensuring no concurrent access to environment variables.
                unsafe { std::env::set_var(self.key, value) };
            } else {
                // SAFETY: We hold ENV_LOCK during all tests that use this guard,
                // ensuring no concurrent access to environment variables.
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

    #[test]
    fn test_parse_valid_bash_input() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("git status".to_string()));
    }

    #[test]
    fn test_parse_non_bash_input() {
        let json = r#"{"tool_name":"Read","tool_input":{"command":"git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn test_parse_missing_command() {
        let json = r#"{"tool_name":"Bash","tool_input":{}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn test_parse_copilot_tool_input_command() {
        let json = r#"{"event":"pre-tool-use","toolName":"run_shell_command","toolInput":{"command":"git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("git status".to_string()));
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
    }

    #[test]
    fn test_parse_copilot_tool_args_json_string() {
        let json = r#"{"event":"pre-tool-use","toolName":"bash","toolArgs":"{\"command\":\"rm -rf /tmp/build\"}"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(
            extract_command(&input),
            Some("rm -rf /tmp/build".to_string())
        );
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
    }

    #[test]
    fn test_parse_gemini_before_tool_input() {
        let json = r#"{
            "session_id":"session-123",
            "transcript_path":"/tmp/transcript.json",
            "cwd":"/tmp",
            "hook_event_name":"BeforeTool",
            "timestamp":"2026-02-24T00:00:00Z",
            "tool_name":"run_shell_command",
            "tool_input":{"command":"git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("git status".to_string()));
        assert_eq!(detect_protocol(&input), HookProtocol::Gemini);
    }

    /// The real Claude Code PreToolUse payload must be answered in Claude's shape.
    ///
    /// Claude Code sends session_id, transcript_path and cwd on every call, and
    /// those were read as "Gemini context" and tested first. dcg then replied
    /// {"decision":"deny"}, which Claude Code does not read — so the guard
    /// denied and the command ran anyway. Every field below is present in a
    /// real invocation; dropping any one of them hides the bug.
    #[test]
    fn test_real_claude_code_payload_is_claude_protocol() {
        let json = r#"{
            "session_id":"9a02fa0e-5133-42",
            "transcript_path":"/dev/null",
            "cwd":"/Users/someone",
            "hook_event_name":"PreToolUse",
            "tool_name":"Bash",
            "tool_input":{"command":"git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("git status".to_string()));
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    /// Each envelope field alone must not flip Claude Code into Gemini either.
    #[test]
    fn test_claude_envelope_fields_do_not_flip_protocol() {
        for field in [
            r#""session_id":"s""#,
            r#""transcript_path":"/dev/null""#,
            r#""cwd":"/tmp""#,
        ] {
            let json = format!(
                r#"{{{field},"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"git status"}}}}"#
            );
            let input: HookInput = serde_json::from_str(&json).unwrap();
            assert_eq!(
                detect_protocol(&input),
                HookProtocol::ClaudeCompatible,
                "field {field} flipped a PreToolUse payload away from Claude"
            );
        }
    }

    #[test]
    fn test_hook_event_name_alone_does_not_force_gemini_protocol() {
        let json = r#"{
            "hook_event_name":"BeforeTool",
            "tool_name":"Bash",
            "tool_input":{"command":"git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("git status".to_string()));
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    #[test]
    fn test_gemini_before_tool_marker_detects_gemini_without_session_fields() {
        let json = r#"{
            "hook_event_name":"BeforeTool",
            "tool_name":"run_shell_command",
            "tool_input":{"command":"git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("git status".to_string()));
        assert_eq!(detect_protocol(&input), HookProtocol::Gemini);
    }

    #[test]
    fn test_gemini_hook_output_json_shape() {
        let output = GeminiHookOutput {
            decision: "deny",
            reason: Cow::Borrowed("blocked for safety"),
            system_message: Some(Cow::Borrowed("BLOCKED by dcg: test")),
            allow_once_code: None,
            allow_once_full_hash: None,
            rule_id: Some("core.git:reset-hard".to_string()),
            pack_id: Some("core.git".to_string()),
            severity: None,
            confidence: None,
            remediation: None,
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["reason"], "blocked for safety");
        assert_eq!(json["systemMessage"], "BLOCKED by dcg: test");
        assert!(json.get("continue").is_none());
        assert!(json.get("stopReason").is_none());
        assert_eq!(json["ruleId"], "core.git:reset-hard");
        assert_eq!(json["packId"], "core.git");
    }

    #[test]
    fn test_parse_non_string_command() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":123}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn test_format_denial_message_includes_explanation_and_rule() {
        let message = format_denial_message(
            "git reset --hard",
            "destructive",
            Some("This is irreversible."),
            Some("core.git"),
            Some("reset-hard"),
            None,
        );

        assert!(message.contains("Reason: destructive"));
        assert!(message.contains("Explanation: This is irreversible."));
        assert!(message.contains("Rule: core.git:reset-hard"));
        assert!(message.contains("Tip: dcg explain"));
    }

    /// The blocked command appears exactly ONCE in the text an agent reads.
    ///
    /// `permissionDecisionReason` is replayed into the transcript on every later
    /// turn of that session, so a second echo is paid per turn forever. It used
    /// to appear twice — the `Tip:` line and a bare `Command:` line — making the
    /// message 2*len(command) + K. The marker is a string no other part of the
    /// message can produce, so a count of 1 is a real count and not a substring
    /// coincidence, and the `\nCommand: ` assertion names the exact line that
    /// must not come back.
    #[test]
    fn denial_message_echoes_command_once() {
        let command = "git reset --hard UNIQUEMARKER7f3a";
        let message = format_denial_message(
            command,
            "destructive",
            Some("This is irreversible."),
            Some("core.git"),
            Some("reset-hard"),
            Some("35836"),
        );

        assert_eq!(
            message.matches("UNIQUEMARKER7f3a").count(),
            1,
            "the command must be echoed exactly once, got:\n{message}"
        );
        assert!(
            message.contains("Tip: dcg explain"),
            "the one surviving echo is the runnable Tip: line, got:\n{message}"
        );
        assert!(
            !message.contains("\nCommand: "),
            "the bare Command: echo is redundant with the Tip: line, got:\n{message}"
        );
    }

    /// The denial text an agent reads must name the escape hatch.
    ///
    /// This string becomes `permissionDecisionReason`, which is all Claude Code
    /// shows its agent. Without the code here the hatch of AGENTS.md §8 is
    /// unreachable from the only place the caller looks.
    #[test]
    fn test_format_denial_message_carries_the_allow_once_code() {
        let message = format_denial_message(
            "git reset --hard",
            "destructive",
            None,
            Some("core.git"),
            Some("reset-hard"),
            Some("35836"),
        );

        assert!(
            message.contains("dcg allow-once 35836"),
            "denial text must quote the runnable allow-once command:\n{message}"
        );
        // The true-positive route keeps the last word.
        assert!(
            message.trim_end().ends_with("run the command manually."),
            "the manual-permission line must remain last:\n{message}"
        );
    }

    /// No code minted, no hatch line — and no dangling placeholder.
    #[test]
    fn test_format_denial_message_omits_the_hatch_when_no_code_exists() {
        let message = format_denial_message(
            "git reset --hard",
            "destructive",
            None,
            Some("core.git"),
            Some("reset-hard"),
            None,
        );

        assert!(
            !message.contains("allow-once"),
            "no code means no allow-once line:\n{message}"
        );
    }

    /// An empty code must not render as a hatch line.
    ///
    /// `dcg allow-once ` with nothing after it is not runnable, and it renders
    /// byte-identical to a real code once the golden mask has replaced the
    /// digits — so without this the guards would stay green over a denial that
    /// offers the agent nothing. `short_code_from_hash` always returns five
    /// digits today; this pins the property rather than the current luck.
    #[test]
    fn test_format_denial_message_treats_an_empty_code_as_no_code() {
        let message = format_denial_message(
            "git reset --hard",
            "destructive",
            None,
            Some("core.git"),
            Some("reset-hard"),
            Some(""),
        );

        assert!(
            !message.contains("allow-once"),
            "an empty code must not produce a hatch line:\n{message}"
        );
    }

    #[test]
    fn test_env_var_guard_restores_value() {
        let _lock = ENV_LOCK.lock().unwrap();
        let key = "DCG_TEST_ENV_GUARD";
        // SAFETY: We hold ENV_LOCK to prevent concurrent env modifications
        unsafe { std::env::remove_var(key) };

        {
            let _guard = EnvVarGuard::set(key, "1");
            assert_eq!(std::env::var(key).as_deref(), Ok("1"));
        }

        assert!(std::env::var(key).is_err());
    }

    // ---------------------------------------------------------------
    // .agent-config-by273: src/hook.rs sat at 47.28% against the 70% floor
    // ci.yml enforces, and that gate had never once run -- the coverage job
    // always died before reaching it. These cover the helpers the e2e
    // spawns never reach: the display helpers, the suggestion routing
    // table, and the two on-disk log writers.
    // ---------------------------------------------------------------

    /// A destructive command used only as test DATA. Assembled rather than
    /// written literally so that editing this file through a shell heredoc
    /// does not trip dcg's own heredoc-body scanner (see spec 333).
    fn rm_rf(path: &str) -> String {
        format!("rm {}rf {path}", '-')
    }

    #[test]
    fn truncate_for_display_leaves_short_strings_alone() {
        let cmd = rm_rf("/");
        assert_eq!(truncate_for_display(&cmd, 32), cmd);
    }

    #[test]
    fn truncate_for_display_leaves_an_exactly_max_length_string_alone() {
        let s = "0123456789";
        assert_eq!(truncate_for_display(s, s.len()), s);
    }

    #[test]
    fn truncate_for_display_appends_an_ellipsis_when_it_cuts() {
        let out = truncate_for_display("0123456789abcdef", 10);
        assert!(out.ends_with("..."), "expected an ellipsis, got {out:?}");
        assert!(
            out.len() <= 10,
            "truncation must not exceed max_len, got {} in {out:?}",
            out.len()
        );
    }

    #[test]
    fn truncate_for_display_does_not_split_a_multibyte_char() {
        // Each emoji is 4 bytes, so a naive &s[..target] byte slice would
        // panic here. The function must land on a char boundary instead.
        let command = format!("{} \u{1f525}\u{1f525}\u{1f525}\u{1f525}", rm_rf(""));
        let out = truncate_for_display(&command, 12);
        assert!(out.ends_with("..."), "expected an ellipsis, got {out:?}");
        assert!(
            command.starts_with(out.trim_end_matches("...")),
            "truncated prefix {out:?} is not a prefix of the input"
        );
    }

    #[test]
    fn truncate_for_display_handles_a_multibyte_char_at_the_cut_point() {
        // 7 ASCII bytes then a 4-byte char, so target = max_len - 3 = 8
        // lands one byte INSIDE the emoji.
        let command = "abcdefg\u{1f525}hij";
        let out = truncate_for_display(command, 11);
        assert!(
            command.starts_with(out.trim_end_matches("...")),
            "truncated prefix {out:?} is not a prefix of the input"
        );
    }

    #[test]
    fn contextual_suggestion_routes_each_command_family() {
        // The table is the contract: a blocked command gets the advice that
        // matches it, not whichever arm happens to fire first.
        let rm_case = rm_rf("/tmp/x");
        let cases: &[(&str, &str)] = &[
            ("git reset --hard", "git stash"),
            ("git checkout .", "git stash"),
            ("git clean -fd", "git clean -n"),
            ("git push --force origin main", "--force-with-lease"),
            (rm_case.as_str(), "Verify the path"),
            ("psql -c 'DROP TABLE users'", "backing up the database"),
            ("kubectl delete pod web", "--dry-run=client"),
            ("docker system prune -af", "docker system df"),
            ("terraform destroy", "terraform plan -destroy"),
        ];
        for (command, expected) in cases {
            let got = get_contextual_suggestion(command)
                .unwrap_or_else(|| panic!("expected a suggestion for {command:?}"));
            assert!(
                got.contains(expected),
                "for {command:?} expected advice containing {expected:?}, got {got:?}"
            );
        }
    }

    #[test]
    fn contextual_suggestion_is_none_for_an_unrecognised_command() {
        assert_eq!(get_contextual_suggestion("echo hello"), None);
    }

    #[test]
    fn build_rule_id_needs_both_halves() {
        assert_eq!(
            build_rule_id(Some("core.filesystem"), Some("rm-rf-general")),
            Some("core.filesystem:rm-rf-general".to_string())
        );
        assert_eq!(build_rule_id(Some("core.filesystem"), None), None);
        assert_eq!(build_rule_id(None, Some("rm-rf-general")), None);
        assert_eq!(build_rule_id(None, None), None);
    }

    #[test]
    fn explain_hint_escapes_quotes_so_it_can_be_pasted() {
        // The hint is advertised as copy-pasteable. An unescaped quote would
        // close the shell string early and run something else.
        let hint = format_explain_hint("sh -c \"echo hi\"");
        assert_eq!(
            hint, "Tip: dcg explain \"sh -c \\\"echo hi\\\"\"",
            "every inner quote must be backslash-escaped"
        );
    }

    #[test]
    fn explanation_text_prefers_a_real_explanation() {
        assert_eq!(
            format_explanation_text(Some("  deletes the repo  "), Some("p:r"), Some("p")),
            "deletes the repo",
            "an explicit explanation wins, and is trimmed"
        );
    }

    #[test]
    fn explanation_text_falls_back_through_rule_then_pack_then_generic() {
        let by_rule = format_explanation_text(None, Some("core.fs:rm-rf"), Some("core.fs"));
        assert!(
            by_rule.contains("core.fs:rm-rf"),
            "the rule id should be named, got {by_rule:?}"
        );

        let by_pack = format_explanation_text(None, None, Some("core.fs"));
        assert!(
            by_pack.contains("core.fs"),
            "the pack should be named, got {by_pack:?}"
        );
        assert!(
            !by_pack.contains("core.fs:"),
            "the pack fallback must not invent a rule id, got {by_pack:?}"
        );

        let generic = format_explanation_text(None, None, None);
        assert!(
            generic.contains("Matched a destructive pattern"),
            "generic fallback, got {generic:?}"
        );
    }

    #[test]
    fn explanation_text_treats_a_blank_explanation_as_absent() {
        // A pack with a whitespace-only description must not print an empty
        // explanation and swallow the rule id.
        let out = format_explanation_text(Some("   "), Some("core.fs:rm-rf"), Some("core.fs"));
        assert!(
            out.contains("core.fs:rm-rf"),
            "a blank explanation must fall through to the rule id, got {out:?}"
        );
    }

    #[test]
    fn explanation_block_indents_continuation_lines() {
        let block = format_explanation_block("first line\nsecond line");
        assert_eq!(block, "Explanation: first line\n             second line");
    }

    #[test]
    fn explanation_block_handles_an_empty_explanation() {
        assert_eq!(format_explanation_block(""), "Explanation:");
    }

    #[test]
    fn severity_maps_one_for_one_to_the_output_theme() {
        use crate::packs::Severity as PackSeverity;
        assert!(matches!(
            to_output_severity(PackSeverity::Critical),
            ThemeSeverity::Critical
        ));
        assert!(matches!(
            to_output_severity(PackSeverity::High),
            ThemeSeverity::High
        ));
        assert!(matches!(
            to_output_severity(PackSeverity::Medium),
            ThemeSeverity::Medium
        ));
        assert!(matches!(
            to_output_severity(PackSeverity::Low),
            ThemeSeverity::Low
        ));
    }

    #[test]
    fn timestamp_is_epoch_seconds() {
        let ts = chrono_lite_timestamp();
        assert!(
            ts.chars().all(|c| c.is_ascii_digit()),
            "timestamp must be bare digits, got {ts:?}"
        );
        let secs: u64 = ts.parse().expect("timestamp must parse as u64");
        // 1_700_000_000 is 2023-11-14. Anything below that means the format
        // changed under us, not that the clock moved.
        assert!(secs > 1_700_000_000, "implausible epoch seconds: {secs}");
    }

    #[test]
    fn log_blocked_command_creates_missing_parents_and_records_the_denial() {
        let dir = tempfile::tempdir().unwrap();
        // Two levels that do not exist yet: the writer must create both.
        let log = dir.path().join("nested/deeper/blocked.log");
        assert!(!log.exists(), "precondition: the log must not exist yet");

        let command = rm_rf("/");
        log_blocked_command(
            log.to_str().unwrap(),
            &command,
            "matched core.filesystem:rm-rf-general",
            Some("core.filesystem"),
        )
        .expect("log_blocked_command should succeed");

        assert!(log.exists(), "the log file must have been created");
        let body = std::fs::read_to_string(&log).unwrap();
        assert!(
            body.contains("core.filesystem"),
            "the pack must be recorded, got {body:?}"
        );
        assert!(
            body.contains("matched core.filesystem:rm-rf-general"),
            "the reason must be recorded, got {body:?}"
        );
        assert!(
            body.contains(&format!("Command: {command}")),
            "the command must be recorded, got {body:?}"
        );
    }

    #[test]
    fn log_blocked_command_appends_rather_than_truncating() {
        // A guard that overwrites its own audit log loses every prior denial.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("blocked.log");
        let path = log.to_str().unwrap();

        let first = rm_rf("/first");
        let second = rm_rf("/second");
        log_blocked_command(path, &first, "one", Some("p")).unwrap();
        log_blocked_command(path, &second, "two", Some("p")).unwrap();

        let body = std::fs::read_to_string(&log).unwrap();
        assert!(
            body.contains(&first),
            "the first denial must survive the second write, got {body:?}"
        );
        assert!(
            body.contains(&second),
            "the second denial must be present, got {body:?}"
        );
    }

    #[test]
    fn log_blocked_command_names_an_unknown_pack() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("blocked.log");

        log_blocked_command(log.to_str().unwrap(), &rm_rf("/"), "no pack", None).unwrap();

        let body = std::fs::read_to_string(&log).unwrap();
        assert!(
            body.contains("[unknown]"),
            "a denial with no pack must still say so, got {body:?}"
        );
    }

    #[test]
    fn log_budget_skip_records_the_stage_and_both_durations() {
        // A budget skip means the evaluator gave up, so the command was
        // allowed WITHOUT being fully checked. This log is the only trace.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("nested/budget.log");

        log_budget_skip(
            log.to_str().unwrap(),
            "git push --force",
            "pack-loop",
            Duration::from_millis(1500),
            Duration::from_millis(1000),
        )
        .expect("log_budget_skip should succeed");

        let body = std::fs::read_to_string(&log).unwrap();
        assert!(
            body.contains("pack-loop"),
            "the stage that gave up must be named, got {body:?}"
        );
        assert!(
            body.contains("Budget: 1000ms"),
            "the budget must be recorded, got {body:?}"
        );
        assert!(
            body.contains("Elapsed: 1500ms"),
            "the elapsed time must be recorded, got {body:?}"
        );
        assert!(
            body.contains("Command: git push --force"),
            "the command must be recorded, got {body:?}"
        );
    }

    #[test]
    fn log_writers_surface_io_errors_instead_of_swallowing_them() {
        // Point the log at a path whose parent is a regular FILE, so
        // create_dir_all must fail. That failure has to reach the caller: a
        // guard that silently drops its audit log is worse than one with none.
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("iam-a-file");
        std::fs::write(&blocker, b"x").unwrap();
        let doomed = blocker.join("nested/blocked.log");
        let doomed = doomed.to_str().unwrap();

        log_blocked_command(doomed, &rm_rf("/"), "r", Some("p"))
            .expect_err("writing under a regular file must fail");

        log_budget_skip(
            doomed,
            "cmd",
            "stage",
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .expect_err("writing under a regular file must fail");
    }

    // ---------------------------------------------------------------
    // The deny path, exercised in-process.
    //
    // These assert that emitting a denial COMPLETES. That is the contract
    // that matters here and it is not a formality: `output_denial*` and
    // `print_colorful_warning` do span arithmetic and width math on an
    // attacker-controlled command string. If any of that panics, the hook
    // dies before writing its JSON, the caller sees no `"deny"`, and the
    // destructive command runs. A guard that panics fails OPEN.
    //
    // The shape of the JSON these write is pinned from the outside, by the
    // subprocess assertions in tests/cli_e2e.rs; these cover the branches
    // those spawns do not reach.
    // ---------------------------------------------------------------

    fn allow_once_fixture() -> AllowOnceInfo {
        AllowOnceInfo {
            code: "12345".to_string(),
            full_hash: "a".repeat(64),
        }
    }

    fn suggestion_fixture() -> Vec<PatternSuggestion> {
        use crate::packs::Platform;
        vec![
            PatternSuggestion {
                command: "git stash",
                description: "save your changes first",
                platform: Platform::All,
            },
            PatternSuggestion {
                command: "trash ./build",
                description: "macOS-only alternative",
                platform: Platform::MacOS,
            },
        ]
    }

    #[test]
    fn every_protocol_emits_a_denial_without_panicking() {
        let command = rm_rf("/var/data");
        let span = MatchSpan {
            start: 0,
            end: command.len(),
        };
        let allow_once = allow_once_fixture();
        let suggestions = suggestion_fixture();

        for protocol in [
            HookProtocol::ClaudeCompatible,
            HookProtocol::Copilot,
            HookProtocol::Gemini,
        ] {
            output_denial_for_protocol(
                protocol,
                &command,
                "matched core.filesystem:rm-rf-general",
                Some("core.filesystem"),
                Some("rm-rf-general"),
                Some("this deletes the tree at /var/data"),
                Some(&allow_once),
                Some(&span),
                Some(crate::packs::Severity::Critical),
                Some(0.97),
                &suggestions,
                true,
            );
        }
    }

    #[test]
    fn a_denial_with_nothing_optional_still_emits() {
        // A legacy pattern denial carries no pack, no rule, no span and no
        // allow-once code. Every Option arm goes None here.
        output_denial(
            &rm_rf("/"),
            "matched a legacy destructive pattern",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            &[],
            false,
        );
    }

    #[test]
    fn a_config_blocklist_denial_withholds_the_bare_hatch() {
        // allow_once_suffices = false is the config-blocklist case: the code
        // is real and still travels in the JSON, but the prose must not tell
        // the user to run a bare `dcg allow-once` that would error.
        let allow_once = allow_once_fixture();
        output_denial(
            "git push --force origin main",
            "blocked by config",
            None,
            None,
            None,
            Some(&allow_once),
            None,
            Some(crate::packs::Severity::High),
            Some(0.5),
            &[],
            false,
        );
    }

    #[test]
    fn the_deny_path_survives_adversarial_commands() {
        // Each of these has broken the display math in some tool before:
        // an empty string, multibyte text, an embedded ANSI escape, a
        // newline, and a command far wider than any terminal.
        let long = "x".repeat(4096);
        let commands = [
            String::new(),
            "\u{1f525}\u{1f525}\u{1f525} \u{4f60}\u{597d} caf\u{e9}".to_string(),
            "echo \u{1b}[31mred\u{1b}[0m".to_string(),
            "line one\nline two\nline three".to_string(),
            long,
        ];

        for command in &commands {
            output_denial(
                command,
                "adversarial input",
                Some("core.filesystem"),
                Some("rm-rf-general"),
                Some("multi\nline\nexplanation"),
                None,
                None,
                Some(crate::packs::Severity::Medium),
                Some(0.1),
                &[],
                true,
            );
        }
    }

    #[test]
    fn a_match_span_past_the_end_of_the_command_does_not_panic() {
        // The span is computed against the NORMALIZED command while the
        // display renders the raw one, so the two can disagree. Slicing on
        // that difference would panic and take the deny with it.
        let command = "git clean -fd";
        let bogus = MatchSpan {
            start: 5,
            end: command.len() + 500,
        };
        output_denial(
            command,
            "span past the end",
            Some("core.git"),
            Some("clean"),
            None,
            None,
            Some(&bogus),
            Some(crate::packs::Severity::Low),
            None,
            &[],
            true,
        );
    }

    #[test]
    fn a_match_span_inside_a_multibyte_char_does_not_panic() {
        // A byte offset that lands mid-character is the classic panic: the
        // emoji occupies bytes 5..9, so this span cuts it in half.
        let command = "echo \u{1f525} done";
        let mid_char = MatchSpan { start: 6, end: 8 };
        output_denial(
            command,
            "span inside a multibyte char",
            Some("core.echo"),
            Some("emoji"),
            None,
            None,
            Some(&mid_char),
            Some(crate::packs::Severity::Low),
            None,
            &[],
            true,
        );
    }

    #[test]
    fn a_warning_emits_with_and_without_an_explanation() {
        // The warn path allows the command, so its only product is this
        // text. If it panics the user is never told anything happened.
        output_warning(
            "git stash drop",
            "warn-only rule matched",
            Some("core.git"),
            Some("stash-drop"),
            Some("this discards a stash entry"),
        );

        output_warning("git stash drop", "warn-only rule matched", None, None, None);

        output_warning(
            "git stash drop",
            "warn-only rule matched",
            Some("core.git"),
            None,
            Some("multi\nline\nexplanation"),
        );
    }
}
