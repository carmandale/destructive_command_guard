//! Command normalization for wrapper prefix stripping.
//!
//! This module strips common wrapper prefixes (sudo, env, backslash escapes, command)
//! so destructive patterns match consistently regardless of how commands are invoked.
//!
//! # Design Principles
//!
//! - **Conservative**: Only strip wrappers when syntax is unambiguous.
//! - **Non-destructive**: Never change the meaning of non-wrapper commands.
//! - **Preserve original**: Return both original and normalized forms for explain output.
//!
//! # Supported Wrappers
//!
//! - `sudo [-EHnkKSb] [-u user] [-g group] ...` - privilege escalation
//! - `env [-i] [-u name] [NAME=VALUE]... command` - environment modification
//! - `\git`, `\rm` - bash alias bypass (leading backslash)
//! - `command [-p] [--] cmd` - but NOT `command -v` or `command -V` (query mode)

use fancy_regex::Regex;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::ops::Range;
use std::sync::LazyLock;

/// Result of command normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedCommand<'a> {
    /// The original command, unchanged.
    pub original: &'a str,
    /// The normalized command with wrappers stripped.
    /// Same as original if no wrappers were stripped.
    pub normalized: Cow<'a, str>,
    /// List of wrappers that were stripped (for explain/debug output).
    pub stripped_wrappers: Vec<StrippedWrapper>,
}

/// A wrapper that was stripped from the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrippedWrapper {
    /// The wrapper type (e.g., "sudo", "env", "backslash", "command").
    pub wrapper_type: &'static str,
    /// The exact text that was stripped.
    pub stripped_text: String,
}

impl<'a> NormalizedCommand<'a> {
    /// Create a new normalized command where no wrappers were stripped.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec::new() is not const-stable
    pub fn unchanged(command: &'a str) -> Self {
        Self {
            original: command,
            normalized: Cow::Borrowed(command),
            stripped_wrappers: Vec::new(),
        }
    }

    /// Check if any normalization was performed.
    #[must_use]
    pub fn was_normalized(&self) -> bool {
        !self.stripped_wrappers.is_empty()
    }
}

/// Normalize a command by stripping common wrapper prefixes.
///
/// Returns the original command alongside the normalized form and a list of
/// stripped wrappers for debugging/explain purposes.
///
/// # Examples
///
/// ```ignore
/// let result = strip_wrapper_prefixes("sudo git reset --hard");
/// assert_eq!(result.normalized, "git reset --hard");
/// assert_eq!(result.stripped_wrappers[0].wrapper_type, "sudo");
/// ```
#[must_use]
pub fn strip_wrapper_prefixes(command: &str) -> NormalizedCommand<'_> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return NormalizedCommand::unchanged(command);
    }

    let mut current = trimmed.to_string();
    let mut stripped_wrappers = Vec::new();

    // Iteratively strip wrappers until no more are found
    // Limit iterations to prevent DoS from maliciously crafted commands
    const MAX_WRAPPER_ITERATIONS: usize = 32;
    let mut iteration_count = 0;
    loop {
        iteration_count += 1;
        if iteration_count > MAX_WRAPPER_ITERATIONS {
            // Too many wrapper layers - treat as suspicious and stop stripping
            break;
        }
        let before_len = current.len();

        // Try stripping each wrapper type in order
        if let Some((remaining, wrapper)) = strip_sudo(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        if let Some((remaining, wrapper)) = strip_env(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        if let Some((remaining, wrapper)) = strip_command_wrapper(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        if let Some((remaining, wrapper)) = strip_leading_backslash(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        // No more wrappers found
        if current.len() == before_len {
            break;
        }
    }

    if stripped_wrappers.is_empty() {
        NormalizedCommand::unchanged(command)
    } else {
        NormalizedCommand {
            original: command,
            normalized: Cow::Owned(current),
            stripped_wrappers,
        }
    }
}

/// Strip `sudo` prefix with its options.
///
/// Handles: `-E`, `-H`, `-n`, `-k`, `-K`, `-S`, `-s`, `-b`, `-i`, `-P`, `-A`, `-B`,
/// `-u <user>`, `-g <group>`, `-h <host>`, `-p <prompt>`, `-C <num>`, `-r <role>`,
/// `-U <user>`, `-D <dir>`, and `--` terminator.
#[allow(clippy::too_many_lines)]
fn strip_sudo(command: &str) -> Option<(String, StrippedWrapper)> {
    // Options that take no argument
    // -s (shell) runs user's shell; if a command follows, it's passed via -c
    // -B (bell) rings bell on password prompt
    const SIMPLE_FLAGS: &[char] = &['E', 'H', 'n', 'k', 'K', 'S', 's', 'b', 'i', 'P', 'A', 'B'];
    // Options that take an argument
    // -D (chdir) changes to directory before running command
    const ARG_FLAGS: &[char] = &['u', 'g', 'h', 'p', 'C', 'r', 'U', 'D', 't', 'a', 'T'];

    let trimmed = command.trim_start();

    // Check for "sudo" or "/path/to/sudo"
    let first_word_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let first_word = &trimmed[..first_word_end];
    let basename = first_word.rsplit('/').next().unwrap_or(first_word);

    if basename != "sudo" {
        return None;
    }

    // Must be followed by whitespace or end
    let after_sudo = &trimmed[first_word.len()..];
    if !after_sudo.is_empty() && !after_sudo.starts_with(char::is_whitespace) {
        return None;
    }

    let rest = after_sudo.trim_start();
    let mut idx = 0;
    let bytes = rest.as_bytes();

    while idx < bytes.len() {
        // Skip whitespace
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }

        // Check for -- terminator
        if bytes[idx] == b'-' && idx + 1 < bytes.len() && bytes[idx + 1] == b'-' {
            // Check if it's exactly "--" followed by whitespace or end
            if idx + 2 >= bytes.len() || bytes[idx + 2].is_ascii_whitespace() {
                idx += 2;
                while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                    idx += 1;
                }
                break;
            }
        }

        if bytes[idx] != b'-' {
            break;
        }

        // Parse one option word (e.g., -E, -EH, -uuser)
        let word_start = idx;
        let mut word_end = idx + 1;
        while word_end < bytes.len() && !bytes[word_end].is_ascii_whitespace() {
            word_end += 1;
        }

        if word_end <= word_start + 1 {
            break;
        }

        let word = &rest[word_start..word_end];
        if word == "--" {
            idx = word_end;
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            break;
        }

        if word.starts_with("--") {
            // Unknown long option - not safe to strip
            return None;
        }

        let mut needs_arg = false;
        let mut unknown_flag = false;
        let mut saw_arg_inline = false;
        let mut chars = word[1..].chars().peekable();

        while let Some(flag) = chars.next() {
            if SIMPLE_FLAGS.contains(&flag) {
                continue;
            }
            if ARG_FLAGS.contains(&flag) {
                if chars.peek().is_some() {
                    // Inline argument (e.g., -uroot)
                    saw_arg_inline = true;
                } else {
                    needs_arg = true;
                }
                // Arg flags consume the rest of the token (if any)
                break;
            }
            unknown_flag = true;
            break;
        }

        if unknown_flag {
            return None;
        }

        idx = word_end;

        if saw_arg_inline {
            continue;
        }

        if needs_arg {
            // Skip whitespace before argument
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            if idx >= bytes.len() {
                // Missing argument - don't strip
                return None;
            }
            // Skip argument token
            idx = consume_word_token(bytes, idx, bytes.len());
        }
    }

    // Skip any remaining whitespace
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }

    let remaining = &rest[idx..];
    if remaining.is_empty() {
        // sudo with no command - don't strip
        return None;
    }

    let stripped_text = trimmed[..trimmed.len() - remaining.len()]
        .trim_end()
        .to_string();

    Some((
        remaining.to_string(),
        StrippedWrapper {
            wrapper_type: "sudo",
            stripped_text,
        },
    ))
}

/// Strip `env` prefix with options and environment variable assignments.
///
/// Handles:
/// - optional path prefix (e.g., `/usr/bin/env`)
/// - options: `-i`, `-u <name>`, `-C <dir>`, `-S <cmd>`, `-f <path>`, `-a <argv0>`, `-0`, `-v`
/// - long options: `--ignore-environment`, `--unset`, `--chdir`, `--split-string`, `--file`,
///   `--argv0`, `--null`, `--debug`, `--ignore-signal`
/// - `NAME=VALUE` assignments
fn strip_env(command: &str) -> Option<(String, StrippedWrapper)> {
    let trimmed = command.trim_start();

    // Check for "env" or "/path/to/env"
    // We split on whitespace to check the first token.
    let first_word_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let first_word = &trimmed[..first_word_end];
    let basename = first_word.rsplit('/').next().unwrap_or(first_word);

    if basename != "env" {
        return None;
    }

    // Must be followed by whitespace or end
    let after_env = &trimmed[first_word.len()..];
    if !after_env.is_empty() && !after_env.starts_with(char::is_whitespace) {
        return None;
    }

    let rest = after_env.trim_start();
    if rest.is_empty() {
        // Just "env" with no args - don't strip (it prints environment)
        return None;
    }

    let bytes = rest.as_bytes();
    let mut idx = 0;

    // Phase 1: Parse options (including -S/--split-string special case)
    match parse_env_options(rest, bytes, idx) {
        EnvParseResult::Continue(new_idx) => idx = new_idx,
        EnvParseResult::Abort => return None,
        EnvParseResult::SplitString(idx, remaining) => {
            let stripped_len = trimmed.len() - rest.len() + idx;
            let stripped_text = trimmed[..stripped_len].trim_end().to_string();
            return Some((
                remaining,
                StrippedWrapper {
                    wrapper_type: "env",
                    stripped_text,
                },
            ));
        }
    }

    // Phase 2: Parse variable assignments (NAME=VALUE)
    idx = parse_env_assignments(bytes, idx);

    // Skip any remaining whitespace
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }

    let remaining = &rest[idx..];
    if remaining.is_empty() {
        // env with no command (just assignments) - don't strip
        return None;
    }

    let stripped_text = trimmed[..trimmed.len() - remaining.len()]
        .trim_end()
        .to_string();

    Some((
        remaining.to_string(),
        StrippedWrapper {
            wrapper_type: "env",
            stripped_text,
        },
    ))
}

enum EnvParseResult {
    Continue(usize),
    SplitString(usize, String),
    Abort,
}

#[allow(clippy::too_many_lines)]
fn parse_env_options(rest: &str, bytes: &[u8], mut idx: usize) -> EnvParseResult {
    let consume_env_arg = |mut idx: usize| -> Option<usize> {
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            return None;
        }
        Some(consume_word_token(bytes, idx, bytes.len()))
    };

    while idx < bytes.len() {
        // Skip whitespace
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }

        // Check for options
        if bytes[idx] != b'-' {
            return EnvParseResult::Continue(idx);
        }

        let word_start = idx;
        let mut word_end = idx + 1;
        while word_end < bytes.len() && !bytes[word_end].is_ascii_whitespace() {
            word_end += 1;
        }
        if word_end <= word_start + 1 {
            break;
        }

        let word = &rest[word_start..word_end];
        if word == "-" {
            // A lone "-" implies -i (ignore environment)
            idx = word_end;
            continue;
        }

        if word == "--" {
            idx = word_end;
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            return EnvParseResult::Continue(idx);
        }

        if word.starts_with("--") {
            let (name, value_opt) = word.find('=').map_or((word, None), |eq_pos| {
                (&word[..eq_pos], Some(&word[eq_pos + 1..]))
            });

            match name {
                "--ignore-environment" | "--null" | "--debug" => {
                    if value_opt.is_some() {
                        return EnvParseResult::Abort;
                    }
                    idx = word_end;
                    continue;
                }
                "--unset" | "--chdir" | "--file" | "--argv0" | "--ignore-signal" => {
                    if value_opt.is_some() {
                        idx = word_end;
                        continue;
                    }
                    let Some(next_idx) = consume_env_arg(word_end) else {
                        return EnvParseResult::Abort;
                    };
                    idx = next_idx;
                    continue;
                }
                "--split-string" => {
                    let raw_arg = if let Some(value) = value_opt {
                        if value.is_empty() {
                            return EnvParseResult::Abort;
                        }
                        value.to_string()
                    } else {
                        let Some(next_idx) = consume_env_arg(word_end) else {
                            return EnvParseResult::Abort;
                        };
                        let arg = &rest[word_end..next_idx];
                        arg.trim_start().to_string()
                    };

                    let unquoted = unquote_env_s_arg(&raw_arg);
                    idx = word_end;
                    if value_opt.is_none() {
                        idx = word_end;
                        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                            idx += 1;
                        }
                        idx = consume_word_token(bytes, idx, bytes.len());
                    }

                    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                        idx += 1;
                    }
                    let rest_of_line = &rest[idx..];
                    let remaining = if rest_of_line.is_empty() {
                        unquoted
                    } else {
                        format!("{unquoted} {rest_of_line}")
                    };
                    return EnvParseResult::SplitString(idx, remaining);
                }
                _ => return EnvParseResult::Abort,
            }
        }

        let word_bytes = word.as_bytes();
        let mut pos = 1;
        while pos < word_bytes.len() {
            let flag = word_bytes[pos] as char;
            match flag {
                'i' | '0' | 'v' => {
                    pos += 1;
                }
                'S' => {
                    let raw_arg = if pos + 1 < word_bytes.len() {
                        word[pos + 1..].to_string()
                    } else {
                        let Some(next_idx) = consume_env_arg(word_end) else {
                            return EnvParseResult::Abort;
                        };
                        let arg = &rest[word_end..next_idx];
                        arg.trim_start().to_string()
                    };

                    let unquoted = unquote_env_s_arg(&raw_arg);
                    idx = word_end;
                    if pos + 1 >= word_bytes.len() {
                        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                            idx += 1;
                        }
                        idx = consume_word_token(bytes, idx, bytes.len());
                    }

                    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                        idx += 1;
                    }
                    let rest_of_line = &rest[idx..];
                    let remaining = if rest_of_line.is_empty() {
                        unquoted
                    } else {
                        format!("{unquoted} {rest_of_line}")
                    };
                    return EnvParseResult::SplitString(idx, remaining);
                }
                'u' | 'P' | 'C' | 'f' | 'a' => {
                    if pos + 1 < word_bytes.len() {
                        idx = word_end;
                    } else {
                        let Some(next_idx) = consume_env_arg(word_end) else {
                            return EnvParseResult::Abort;
                        };
                        idx = next_idx;
                    }
                    pos = word_bytes.len();
                }
                _ => return EnvParseResult::Abort,
            }
        }

        if idx < word_end {
            idx = word_end;
        }
    }
    EnvParseResult::Continue(idx)
}

fn parse_env_assignments(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() {
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }

        let start = idx;
        let end = consume_word_token(bytes, idx, bytes.len());
        if start >= end {
            return start;
        }

        let word_bytes = &bytes[start..end];
        let has_equals = word_bytes.iter().position(|b| *b == b'=');

        if has_equals.is_some_and(|pos| pos > 0) {
            if token_has_inline_code(word_bytes) {
                return start;
            }
            idx = end;
            continue;
        }

        return start;
    }

    idx
}

fn token_has_inline_code(token: &[u8]) -> bool {
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while i < token.len() {
        let byte = token[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }

        if byte == b'\\' && !in_single {
            escaped = true;
            i = (i + 1).min(token.len());
            continue;
        }

        match byte {
            b'\'' if !in_double => {
                in_single = !in_single;
            }
            b'"' if !in_single => {
                in_double = !in_double;
            }
            b'`' if !in_single => return true,
            b'$' if !in_single && i + 1 < token.len() && token[i + 1] == b'(' => return true,
            _ => {}
        }

        i += 1;
    }

    false
}
fn unquote_env_s_arg(arg: &str) -> String {
    let bytes = arg.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return arg[1..arg.len() - 1].to_string();
        }
    }
    arg.to_string()
}

/// Strip `command` wrapper, but NOT when used in query mode (`-v`/`-V`).
fn strip_command_wrapper(command: &str) -> Option<(String, StrippedWrapper)> {
    let trimmed = command.trim_start();

    // Check for "command" or "/path/to/command"
    let first_word_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let first_word = &trimmed[..first_word_end];
    let basename = first_word.rsplit('/').next().unwrap_or(first_word);

    if basename != "command" {
        return None;
    }

    // Must be followed by whitespace or end
    let after_command = &trimmed[first_word.len()..];
    if !after_command.is_empty() && !after_command.starts_with(char::is_whitespace) {
        return None;
    }

    let rest = after_command.trim_start();
    if rest.is_empty() {
        return None;
    }

    let mut idx = 0;
    let bytes = rest.as_bytes();

    while idx < bytes.len() {
        // Skip whitespace
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }

        if bytes[idx] != b'-' {
            break;
        }

        // Parse one option word (e.g., -p, -pv, --)
        let word_start = idx;
        let mut word_end = idx + 1;
        while word_end < bytes.len() && !bytes[word_end].is_ascii_whitespace() {
            word_end += 1;
        }

        if word_end <= word_start + 1 {
            break;
        }

        let word = &rest[word_start..word_end];
        if word == "--" {
            idx = word_end;
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            break;
        }
        if word.starts_with("--") {
            // Unknown long option - not safe to strip
            return None;
        }

        let mut unknown = false;
        for flag in word[1..].chars() {
            match flag {
                'v' | 'V' => {
                    // Query mode - NOT a wrapper
                    return None;
                }
                'p' => {}
                _ => {
                    unknown = true;
                    break;
                }
            }
        }
        if unknown {
            return None;
        }

        idx = word_end;
    }

    // Skip any remaining whitespace
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }

    let remaining = &rest[idx..];
    if remaining.is_empty() {
        return None;
    }

    let stripped_text = trimmed[..trimmed.len() - remaining.len()]
        .trim_end()
        .to_string();

    Some((
        remaining.to_string(),
        StrippedWrapper {
            wrapper_type: "command",
            stripped_text,
        },
    ))
}

#[must_use]
pub fn consume_word_token(bytes: &[u8], mut i: usize, len: usize) -> usize {
    while i < len {
        let b = bytes[i];

        if b.is_ascii_whitespace() {
            break;
        }

        if matches!(b, b'|' | b';' | b'&' | b'(' | b')') {
            break;
        }

        match b {
            b'\\' => {
                // Handle CRLF escape (consumes 3 bytes: \, \r, \n)
                if i + 2 < len && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                    i += 3;
                } else {
                    // Skip escaped byte. This is conservative for UTF-8.
                    i = (i + 2).min(len);
                }
            }
            b'\'' => {
                // Single-quoted segment
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'"' => {
                // Double-quoted segment
                i += 1;
                while i < len {
                    match bytes[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' => {
                            i = (i + 2).min(len);
                        }
                        _ => {
                            i += 1;
                        }
                    }
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    i
}

/// Regex to strip absolute paths from git/rm binaries.
///
/// Handles both Unix paths (`/path/to/bin/git`) and Windows paths (`C:/path/to/git.exe`).
/// For Windows, matches drive letters (C:) followed by either forward or back slashes.
pub static PATH_NORMALIZER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:",
        // Unix paths ending in bin/
        r"/(?:\S*/)*s?bin/",
        r"|",
        // Windows paths: drive letter followed by path
        // Handles both C:/ and C:\ style paths
        // Uses [^\s]* to match path segments (note: won't handle spaces in paths)
        r"[A-Za-z]:[/\\](?:[^\s/\\]*[/\\])*",
        r")",
        // Capture the binary name
        r"(rm|git)",
        // Optional .exe extension for Windows
        r"(?:\.exe)?",
        // Must be followed by whitespace or end
        r"(?=\s|$)"
    ))
    .unwrap()
});

/// Regex for normalizing quoted paths that may contain spaces.
///
/// Handles commands like:
/// - `"C:/Program Files/Git/bin/git.exe" status` → `git status`
/// - `"/usr/local/bin/git" status` → `git status`
///
/// This regex matches:
/// - Opening double quote
/// - A path (Unix or Windows, may contain spaces)
/// - The binary name (git, rm)
/// - Optional .exe extension
/// - Closing double quote
pub static QUOTED_PATH_NORMALIZER: LazyLock<Regex> = LazyLock::new(|| {
    // Matches quoted paths like "C:/Program Files/Git/bin/git.exe" or "/usr/bin/git"
    // Note: Uses [^"]+ to match path content (may include spaces)
    Regex::new(r#"^"(?:[^"]+/|[A-Za-z]:[^"]+[/\\])(rm|git)(?:\.exe)?""#).unwrap()
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizeTokenKind {
    Word,
    Separator,
}

#[derive(Debug, Clone)]
pub struct NormalizeToken {
    pub kind: NormalizeTokenKind,
    pub byte_range: Range<usize>,
}

impl NormalizeToken {
    #[inline]
    #[must_use]
    pub fn text<'a>(&self, command: &'a str) -> Option<&'a str> {
        command.get(self.byte_range.clone())
    }
}

pub type NormalizeTokens = SmallVec<[NormalizeToken; 16]>;

#[must_use]
pub fn tokenize_for_normalization(command: &str) -> NormalizeTokens {
    let bytes = command.as_bytes();
    let len = bytes.len();

    let mut tokens = NormalizeTokens::new();
    let mut i = 0;

    while i < len {
        i = skip_ascii_whitespace(bytes, i, len);
        if i >= len {
            break;
        }

        if bytes[i] == b'\n' {
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Separator,
                byte_range: i..i + 1,
            });
            i += 1;
            continue;
        }

        if let Some(end) = consume_separator_token(bytes, i, len, &mut tokens) {
            i = end;
            continue;
        }

        let start = i;
        let end = consume_word_token(bytes, i, len);
        i = end;

        if start < i {
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Word,
                byte_range: start..i,
            });
        }
    }

    tokens
}

#[inline]
#[must_use]
pub fn skip_ascii_whitespace(bytes: &[u8], mut i: usize, len: usize) -> usize {
    while i < len && bytes[i].is_ascii_whitespace() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

#[inline]
pub fn consume_separator_token(
    bytes: &[u8],
    i: usize,
    len: usize,
    tokens: &mut NormalizeTokens,
) -> Option<usize> {
    match bytes[i] {
        b'|' => {
            let end = if i + 1 < len && bytes[i + 1] == b'|' {
                i + 2
            } else {
                i + 1
            };
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Separator,
                byte_range: i..end,
            });
            Some(end)
        }
        b';' | b'(' | b')' => {
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Separator,
                byte_range: i..i + 1,
            });
            Some(i + 1)
        }
        b'&' => {
            let end = if i + 1 < len && bytes[i + 1] == b'&' {
                i + 2
            } else {
                i + 1
            };
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Separator,
                byte_range: i..end,
            });
            Some(end)
        }
        _ => None,
    }
}

#[inline]
#[must_use]
pub fn is_env_assignment(word: &str) -> bool {
    // Rough heuristic for KEY=VALUE words used as env assignments.
    let Some((key, _value)) = word.split_once('=') else {
        return false;
    };
    !key.is_empty()
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !word.starts_with('-')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizeWrapper {
    None,
    Sudo { options_ended: bool, skip_next: u8 },
    Env { options_ended: bool, skip_next: u8 },
    Command { options_ended: bool, skip_next: u8 },
    CommandQuery,
}

impl NormalizeWrapper {
    #[inline]
    #[must_use]
    pub fn from_command_word(word: &str) -> Option<Self> {
        let base_name = word.rsplit('/').next().unwrap_or(word);
        match base_name {
            "sudo" => Some(Self::Sudo {
                options_ended: false,
                skip_next: 0,
            }),
            "env" => Some(Self::Env {
                options_ended: false,
                skip_next: 0,
            }),
            "command" => Some(Self::Command {
                options_ended: false,
                skip_next: 0,
            }),
            _ => None,
        }
    }

    #[inline]
    #[must_use]
    pub fn should_skip_token(self, word: &str) -> bool {
        match self {
            Self::None | Self::CommandQuery => false,
            Self::Sudo {
                options_ended,
                skip_next,
            }
            | Self::Env {
                options_ended,
                skip_next,
            }
            | Self::Command {
                options_ended,
                skip_next,
            } => {
                if skip_next > 0 {
                    return true;
                }
                if !options_ended && word == "--" {
                    return true;
                }
                !options_ended && word.starts_with('-')
            }
        }
    }

    #[inline]
    #[must_use]
    fn advance_sudo(mut options_ended: bool, mut skip_next: u8, word: &str) -> Self {
        if skip_next > 0 {
            skip_next = skip_next.saturating_sub(1);
            return Self::Sudo {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && word == "--" {
            options_ended = true;
            return Self::Sudo {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && word.starts_with('-') {
            // Options that take an argument: -u USER, -g GROUP, -h HOST, -p PROMPT
            // Also support attached args: -uUSER, -gGROUP, etc (no extra token to skip).
            let takes_value = matches!(word, "-u" | "-g" | "-h" | "-p")
                || word.starts_with("-u")
                || word.starts_with("-g")
                || word.starts_with("-h")
                || word.starts_with("-p");
            if takes_value && word.len() == 2 {
                skip_next = 1;
            }
            return Self::Sudo {
                options_ended,
                skip_next,
            };
        }
        Self::Sudo {
            options_ended,
            skip_next,
        }
    }

    #[inline]
    #[must_use]
    fn advance_env(mut options_ended: bool, mut skip_next: u8, word: &str) -> Self {
        if skip_next > 0 {
            skip_next = skip_next.saturating_sub(1);
            return Self::Env {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && word == "--" {
            options_ended = true;
            return Self::Env {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && word.starts_with('-') {
            // `env -u NAME ...` unsets a variable (takes an argument).
            let takes_value = word == "-u" || word == "--unset" || word.starts_with("-u");
            if takes_value && (word == "-u" || word == "--unset") {
                skip_next = 1;
            }
            return Self::Env {
                options_ended,
                skip_next,
            };
        }
        Self::Env {
            options_ended,
            skip_next,
        }
    }

    #[inline]
    #[must_use]
    fn advance_command(mut options_ended: bool, skip_next: u8, word: &str) -> Self {
        let mut skip_next = skip_next;
        if skip_next > 0 {
            skip_next = skip_next.saturating_sub(1);
            return Self::Command {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && word == "--" {
            options_ended = true;
            return Self::Command {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && word.starts_with('-') {
            // `command -v/-V` queries command resolution (not a wrapper execution).
            if matches!(word, "-v" | "-V") {
                return Self::CommandQuery;
            }
            // `command -p` is wrapper-like (no value).
            return Self::Command {
                options_ended,
                skip_next,
            };
        }
        Self::Command {
            options_ended,
            skip_next,
        }
    }

    #[inline]
    #[must_use]
    pub fn advance(self, word: &str) -> Self {
        match self {
            Self::Sudo {
                options_ended,
                skip_next,
            } => Self::advance_sudo(options_ended, skip_next, word),
            Self::Env {
                options_ended,
                skip_next,
            } => Self::advance_env(options_ended, skip_next, word),
            Self::Command {
                options_ended,
                skip_next,
            } => Self::advance_command(options_ended, skip_next, word),
            Self::None | Self::CommandQuery => self,
        }
    }
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn normalize_command_word_token(token: &str) -> Option<String> {
    let mut out = token.to_string();

    // Strip line continuations (backslash + newline) anywhere in the token
    let mut changed = if out.contains("\\\n") || out.contains("\\\r\n") {
        out = out.replace("\\\n", "").replace("\\\r\n", "");
        true
    } else {
        false
    };

    let stripped = out.trim_start_matches('\\');
    if !stripped.is_empty() && stripped.len() != out.len() {
        // Only strip leading backslashes when it looks like an escaped command word.
        // This avoids turning escaped quotes (e.g., `\"`) into real quotes, which can
        // change tokenization on subsequent normalization passes.
        let first = stripped.as_bytes()[0];
        let looks_like_command =
            first.is_ascii_alphanumeric() || matches!(first, b'/' | b'.' | b'_' | b'~');
        if looks_like_command {
            out = stripped.to_string();
            changed = true;
        }
    }

    // Strip internal backslash escapes before regular ASCII letters.
    // In bash, `g\it` is equivalent to `git` because backslash makes the next char literal.
    // We only strip backslashes before alphanumeric chars to avoid breaking special escapes.
    if out.contains('\\') {
        let mut result = String::with_capacity(out.len());
        let mut chars = out.chars().peekable();
        let mut local_changed = false;
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    // Only strip backslash before regular letters/digits (not special chars)
                    if next.is_ascii_alphanumeric() {
                        // Skip the backslash, keep the letter
                        local_changed = true;
                        continue;
                    }
                }
            }
            result.push(c);
        }
        if local_changed {
            out = result;
            changed = true;
        }
    }

    // Handle mixed quoting concatenation: g'i't -> git, "g"it -> git, etc.
    // In bash, adjacent quoted and unquoted sections concatenate into a single word.
    #[allow(clippy::while_let_on_iterator)]
    if (out.contains('\'') || out.contains('"')) && out.len() > 2 {
        let mut result = String::with_capacity(out.len());
        let mut chars = out.chars();
        let mut local_changed = false;
        while let Some(c) = chars.next() {
            if c == '\'' || c == '"' {
                let quote = c;
                // Look for matching close quote
                let mut found_close = false;
                let mut inner_str = String::new();
                while let Some(inner) = chars.next() {
                    if inner == quote {
                        found_close = true;
                        local_changed = true;
                        break;
                    }
                    inner_str.push(inner);
                }
                if !found_close {
                    // Unclosed quote - put quote back and keep the rest as is
                    result.push(quote);
                }
                result.push_str(&inner_str);
            } else {
                result.push(c);
            }
        }
        if local_changed {
            out = result;
            changed = true;
        }
    }

    // Strip Windows .exe extension from command words (e.g., git.exe -> git)
    if out.to_ascii_lowercase().ends_with(".exe") && out.len() > 4 {
        out.truncate(out.len() - 4);
        changed = true;
    }

    // Also strip .exe from inside quotes (e.g., "C:/path/git.exe" -> "C:/path/git")
    // This handles Windows paths with spaces that need to stay quoted
    let quote_check = match (out.as_bytes().first(), out.as_bytes().last()) {
        (Some(b'"'), Some(b'"')) if out.len() > 6 => {
            Some((b'"', out[1..out.len() - 1].to_string()))
        }
        (Some(b'\''), Some(b'\'')) if out.len() > 6 => {
            Some((b'\'', out[1..out.len() - 1].to_string()))
        }
        _ => None,
    };
    if let Some((q, inner)) = quote_check {
        if inner.to_ascii_lowercase().ends_with(".exe") {
            let inner_stripped = &inner[..inner.len() - 4];
            out = format!("{}{inner_stripped}{}", q as char, q as char);
            changed = true;
        }
    }

    // Check for matching quotes (both must be same type)
    let quote = match (out.as_bytes().first(), out.as_bytes().last()) {
        (Some(b'\''), Some(b'\'')) => Some(b'\''),
        (Some(b'"'), Some(b'"')) => Some(b'"'),
        _ => None,
    };

    if let Some(q) = quote {
        if out.len() >= 2 {
            let inner = &out[1..out.len() - 1];
            // Only unquote when it's clearly a single-token command word (no whitespace/separators).
            let inner_bytes = inner.as_bytes();
            let is_safe = !inner_bytes.is_empty()
                && !inner_bytes.iter().any(u8::is_ascii_whitespace)
                && !inner_bytes
                    .iter()
                    .any(|b| matches!(b, b'|' | b';' | b'&' | b'(' | b')'))
                && inner_bytes.first().is_some_and(|b| *b != q);

            if is_safe {
                out = inner.to_string();
                changed = true;
            }
        }
    }

    if changed { Some(out) } else { None }
}

#[inline]
fn looks_like_subcommand_word(token: &str) -> bool {
    // Treat only simple alnum/underscore/dash words as subcommands.
    //
    // This intentionally excludes common path-like/expansion-like tokens (/, ., ~, $),
    // because stripping their quotes can change semantics for downstream parsers (e.g. rm).
    if token.is_empty() {
        return false;
    }

    let first = token.as_bytes()[0];
    if matches!(first, b'/' | b'.' | b'~' | b'$') {
        return false;
    }

    token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

#[must_use]
fn normalize_subcommand_token(token: &str) -> Option<String> {
    let mut out = token.to_string();
    // Strip line continuations (backslash + newline) anywhere in the token
    let mut changed = if out.contains("\\\n") || out.contains("\\\r\n") {
        out = out.replace("\\\n", "").replace("\\\r\n", "");
        true
    } else {
        false
    };

    // Check for matching quotes (both must be same type)
    let quote = match (out.as_bytes().first(), out.as_bytes().last()) {
        (Some(b'\''), Some(b'\'')) => Some(b'\''),
        (Some(b'"'), Some(b'"')) => Some(b'"'),
        _ => None,
    };

    if let Some(q) = quote {
        if out.len() >= 2 {
            let inner = &out[1..out.len() - 1];
            // Only unquote when it's clearly a single-token command-ish word (no whitespace/separators).
            let inner_bytes = inner.as_bytes();
            let is_safe = !inner_bytes.is_empty()
                && !inner_bytes.iter().any(u8::is_ascii_whitespace)
                && !inner_bytes
                    .iter()
                    .any(|b| matches!(b, b'|' | b';' | b'&' | b'(' | b')'))
                && inner_bytes.first().is_some_and(|b| *b != q)
                && looks_like_subcommand_word(inner);

            if is_safe {
                out = inner.to_string();
                changed = true;
            }
        }
    }

    if changed { Some(out) } else { None }
}

/// Normalize wrapper/segment command words for matching.
///
/// This removes harmless quoting around *executed* command tokens:
/// - `"git" reset --hard` → `git reset --hard`
/// - `sudo "/bin/rm" -rf /etc` → `sudo /bin/rm -rf /etc`
/// - `git.exe reset --hard` → `git reset --hard`
///
/// Quoted **arguments** are intentionally left alone *unless* they look like
/// subcommand words (e.g., `git "reset" --hard`). Path-like tokens (e.g. quoted
/// `/tmp/...` or `$TMPDIR/...`) keep their quoting, because stripping it can
/// change semantics for downstream parsers (notably `rm`).
#[must_use]
/// Is the token starting at `token_start` a heredoc (or here-string) delimiter?
///
/// True when the bytes immediately before it, ignoring blanks, end in `<<`, `<<-`
/// or `<<<`. Blanks only: a newline ends the heredoc's own line, so a quoted word
/// on the following line is an ordinary token, not this operator's delimiter.
///
/// Deliberately textual. The tokenizer does not mark operators, and inferring the
/// relationship from token adjacency would depend on how `<<` happens to be split
/// today (`.agent-config-1vfil`).
fn is_heredoc_delimiter_token(command: &str, token_start: usize) -> bool {
    let before = &command.as_bytes()[..token_start];
    let end = before
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t'))
        .map_or(0, |i| i + 1);
    let head = &before[..end];

    // `<<-` is the tab-stripping form; the `-` sits between the operator and the
    // delimiter, so step over it before looking for the operator itself.
    let head = head.strip_suffix(b"-").unwrap_or(head);
    head.ends_with(b"<<")
}

pub fn dequote_segment_command_words(command: &str) -> Cow<'_, str> {
    // Fast path: most commands contain no quotes, backslashes, or .exe extensions
    // that need normalization. Check for these special cases to enable normalization.
    let needs_normalization = command
        .as_bytes()
        .iter()
        .any(|b| matches!(b, b'\'' | b'"' | b'\\'))
        || command.to_ascii_lowercase().contains(".exe");

    if !needs_normalization {
        return Cow::Borrowed(command);
    }

    let tokens = tokenize_for_normalization(command);
    if tokens.is_empty() {
        return Cow::Borrowed(command);
    }

    let mut replacements: Vec<(Range<usize>, String)> = Vec::new();
    let mut segment_has_cmd = false;
    let mut current_cmd_word: Option<String> = None;
    let mut wrapper: NormalizeWrapper = NormalizeWrapper::None;

    for tok in &tokens {
        if tok.kind == NormalizeTokenKind::Separator {
            segment_has_cmd = false;
            current_cmd_word = None;
            wrapper = NormalizeWrapper::None;
            continue;
        }

        let Some(token_text) = tok.text(command) else {
            // If we can't safely slice, fail open.
            return Cow::Borrowed(command);
        };

        if segment_has_cmd {
            // Check if we should skip dequoting for this command
            if let Some(cmd) = &current_cmd_word {
                if crate::context::SAFE_STRING_REGISTRY.is_all_args_data(cmd) {
                    continue;
                }
            }

            // A heredoc delimiter's quotes are not decoration: they decide whether the
            // shell expands the body before the receiver ever sees it. Dequoting
            // `cat << 'EOF'` into `cat << EOF` changes what the command MEANS, and
            // downstream masking then reads an unquoted delimiter the user never wrote
            // (.agent-config-1vfil). Only the spaced spellings were affected — with no
            // space, `<<'EOF'` is a single token and never reached this branch — which
            // is why every arm table in spec 333 missed it.
            if is_heredoc_delimiter_token(command, tok.byte_range.start) {
                continue;
            }

            // Normalize subcommand-like words (e.g. git "reset" -> git reset), but do NOT strip
            // quoting from path-like tokens (e.g. rm "/tmp/foo", rm "$TMPDIR/foo").
            if let Some(replacement) = normalize_subcommand_token(token_text) {
                replacements.push((tok.byte_range.clone(), replacement));
            }
            continue;
        }

        let current = token_text;

        // `command -v/-V ...` is a query, not execution.
        if matches!(wrapper, NormalizeWrapper::CommandQuery) {
            segment_has_cmd = true;
            wrapper = NormalizeWrapper::None;
            continue;
        }

        // Wrapper option (or wrapper option argument) - consume and continue.
        if wrapper.should_skip_token(current) {
            wrapper = wrapper.advance(current);
            continue;
        }

        // If a wrapper is active and this token isn't an option/assignment, the wrapper is done.
        if !matches!(wrapper, NormalizeWrapper::None) {
            wrapper = NormalizeWrapper::None;
        }

        // If we haven't found the command word yet, check wrappers/assignments.
        if let Some(next_wrapper) = NormalizeWrapper::from_command_word(current) {
            wrapper = next_wrapper;
            continue;
        }

        if is_env_assignment(current) {
            continue;
        }

        // Found the segment's command word.
        segment_has_cmd = true;

        let replacement = normalize_command_word_token(current);
        // Track the normalized command word for safe registry checks
        current_cmd_word = Some(replacement.clone().unwrap_or_else(|| current.to_string()));

        if let Some(repl) = replacement {
            replacements.push((tok.byte_range.clone(), repl));
        }
    }

    if replacements.is_empty() {
        return Cow::Borrowed(command);
    }

    // Apply replacements in-order.
    replacements.sort_by_key(|(r, _)| r.start);
    let mut out = String::with_capacity(command.len());
    let mut last = 0usize;
    for (range, replacement) in replacements {
        if range.start > last {
            out.push_str(&command[last..range.start]);
        }
        out.push_str(&replacement);
        last = range.end;
    }
    if last < command.len() {
        out.push_str(&command[last..]);
    }

    Cow::Owned(out)
}

/// Try to normalize a command using path normalizers.
///
/// Tries `PATH_NORMALIZER` first (for unquoted paths), then `QUOTED_PATH_NORMALIZER`
/// (for quoted paths that may contain spaces).
fn apply_path_normalizers(base: &str) -> Option<String> {
    // Try unquoted path normalizer first
    if let Ok(Cow::Owned(replaced)) = PATH_NORMALIZER.try_replacen(base, 1, "$1") {
        return Some(replaced);
    }
    // Try quoted path normalizer for paths like "C:/Program Files/Git/bin/git"
    if let Ok(Cow::Owned(replaced)) = QUOTED_PATH_NORMALIZER.try_replacen(base, 1, "$1") {
        return Some(replaced);
    }
    None
}

/// Restore the word break that an unquoted redirection operator already makes.
///
/// `>` and `<` are shell metacharacters: they end the current word wherever they
/// appear, so `git>/dev/null reset --hard` runs exactly what
/// `git >/dev/null reset --hard` runs. Pack patterns anchor the command word with
/// `git\s+`, so the glued spelling matched nothing and the guard allowed a real
/// destructive invocation (`.agent-config-6yt2i`). Writing the space the shell
/// already implies lets every existing pattern see the command word it was
/// written for, instead of teaching each pattern about redirections.
///
/// Left exactly as written:
/// - quoted and backslash-escaped `>`/`<`, which are data, not operators;
/// - heredoc and here-string operators (`<<`, `<<<`), whose tokenization the
///   heredoc masker owns — re-spacing them would change which delimiter it reads;
/// - a file-descriptor prefix that is already its own word (`cmd 2>&1`), where
///   the word ended before the digits and no break is missing.
#[must_use]
pub fn split_glued_redirections(command: &str) -> Cow<'_, str> {
    let bytes = command.as_bytes();
    if !bytes.iter().any(|b| matches!(b, b'>' | b'<')) {
        return Cow::Borrowed(command);
    }

    let len = bytes.len();
    let mut out: Option<String> = None;
    let mut copied = 0usize;
    let mut i = 0usize;

    while i < len {
        match bytes[i] {
            b'\\' => {
                // Escaped byte: `\>` is a literal, not an operator.
                i = (i + 2).min(len);
            }
            b'\'' => {
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'"' => {
                i += 1;
                while i < len {
                    match bytes[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' => {
                            i = (i + 2).min(len);
                        }
                        _ => i += 1,
                    }
                }
            }
            b'<' if i + 1 < len && bytes[i + 1] == b'<' => {
                // Heredoc (`<<`) or here-string (`<<<`): not ours to re-space.
                i += 2;
                if i < len && bytes[i] == b'<' {
                    i += 1;
                }
            }
            b'>' | b'<' => {
                // `&>` redirects both streams; the `&` belongs to the operator,
                // so the break goes in front of it.
                let mut op_start = i;
                if bytes[i] == b'>' && op_start > 0 && bytes[op_start - 1] == b'&' {
                    op_start -= 1;
                }

                // Walk back over an fd prefix (`2>`, `10>>`). If only digits stand
                // between the operator and whitespace, the previous word already
                // ended and nothing is glued.
                let mut word_end = op_start;
                while word_end > 0 && bytes[word_end - 1].is_ascii_digit() {
                    word_end -= 1;
                }
                let fd_prefix_is_its_own_word = word_end < op_start
                    && (word_end == 0 || bytes[word_end - 1].is_ascii_whitespace());

                if op_start > 0
                    && !bytes[op_start - 1].is_ascii_whitespace()
                    && !fd_prefix_is_its_own_word
                {
                    let buf = out.get_or_insert_with(|| String::with_capacity(len + 4));
                    buf.push_str(&command[copied..op_start]);
                    buf.push(' ');
                    copied = op_start;
                }

                // Consume the whole operator so `>>` is not re-examined.
                while i < len && matches!(bytes[i], b'>' | b'<') {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    match out {
        Some(mut buf) => {
            buf.push_str(&command[copied..]);
            Cow::Owned(buf)
        }
        None => Cow::Borrowed(command),
    }
}

/// A pipeline operator, a list operator, a newline, a grouping paren or a
/// command substitution backtick all end the simple command a redirection
/// belongs to, and so bound how far it may move.
#[inline]
const fn ends_simple_command(b: u8) -> bool {
    matches!(b, b';' | b'\n' | b'|' | b'&' | b'(' | b')' | b'`')
}

/// Move each redirection to the end of the simple command it belongs to.
///
/// A redirection is position-independent: `rm >/dev/null -rf /` runs exactly
/// what `rm -rf / >/dev/null` runs, because the shell strips the operator and
/// its target out of the argument list before `rm` is executed. Pack patterns
/// spell a command and its arguments as one run of tokens (`rm\s+-rf`,
/// `reset\s+--hard`), so a redirection parked between them walked through the
/// guard while the trailing spelling denied (`.agent-config-y1h6c`). Rewriting
/// the command the way the shell reads it lets every existing pattern see the
/// command line it was written for, instead of teaching each pattern an
/// optional redirection absorber at every token boundary.
///
/// Moved, not deleted, because some patterns match ON a redirection --
/// `sqlite3 <db> < dump.sql` is one -- and the end of the command is exactly
/// where those patterns already look for it.
///
/// Left exactly as written:
/// - any command carrying a heredoc or here-string operator (`<<`, `<<<`),
///   whose body is data the masker reads verbatim and whose tokenization it
///   owns -- moving a word across it would rewrite the body;
/// - quoted and backslash-escaped `>`/`<`, which are data, not operators;
/// - a redirection that already ends its command, which is where it belongs.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn move_redirections_to_segment_end(command: &str) -> Cow<'_, str> {
    let bytes = command.as_bytes();
    if !bytes.iter().any(|b| matches!(b, b'>' | b'<')) {
        return Cow::Borrowed(command);
    }

    let len = bytes.len();
    // Per segment: where it ends, the redirections in it (own bytes, plus the
    // end of the whitespace to swallow when one is cut), and the last byte in
    // it that belongs to an ordinary word.
    type Segment = (usize, Vec<(Range<usize>, usize)>, Option<usize>);
    let mut segments: Vec<Segment> = Vec::new();
    let mut runs: Vec<(Range<usize>, usize)> = Vec::new();
    let mut last_word_byte: Option<usize> = None;
    let mut i = 0usize;

    while i < len {
        match bytes[i] {
            b'\\' => {
                // Escaped byte: `\>` is a literal, not an operator.
                i = (i + 2).min(len);
                last_word_byte = Some(i.saturating_sub(1));
            }
            b'\'' => {
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
                last_word_byte = Some(i.saturating_sub(1));
            }
            b'"' => {
                i += 1;
                while i < len {
                    match bytes[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' => i = (i + 2).min(len),
                        _ => i += 1,
                    }
                }
                last_word_byte = Some(i.saturating_sub(1));
            }
            // Heredoc (`<<`) or here-string (`<<<`): the body below is data this
            // rewrite must not reach, so the whole command is left alone.
            b'<' if i + 1 < len && bytes[i + 1] == b'<' => return Cow::Borrowed(command),
            // `&>` is a redirection operator; a lone `&` ends the command.
            b'>' | b'<' | b'&' if bytes[i] != b'&' || (i + 1 < len && bytes[i + 1] == b'>') => {
                let (run, cut_end) = consume_redirection_run(bytes, i, len);
                i = run.end;
                // A file-descriptor prefix (`2>&1`) was read as an ordinary word
                // one byte at a time before the operator identified it. It is
                // part of the redirection, not an argument that follows one.
                if last_word_byte.is_some_and(|w| w >= run.start) {
                    last_word_byte = None;
                }
                runs.push((run, cut_end));
            }
            b if ends_simple_command(b) => {
                segments.push((i, std::mem::take(&mut runs), last_word_byte.take()));
                i += 1;
            }
            b => {
                if !b.is_ascii_whitespace() {
                    last_word_byte = Some(i);
                }
                i += 1;
            }
        }
    }
    segments.push((len, runs, last_word_byte));

    // A redirection moves only when an ordinary word follows it in the same
    // command. One that is already last -- including one trailed only by more
    // redirections, whose ORDER is the shell's own (`>out 2>&1` is not
    // `2>&1 >out`) -- is left byte for byte where it was written.
    let mut moved_any = false;
    for (_, runs, last_word_byte) in &segments {
        let Some(word_end) = *last_word_byte else {
            continue;
        };
        if runs.iter().any(|(run, _)| run.end <= word_end) {
            moved_any = true;
            break;
        }
    }
    if !moved_any {
        return Cow::Borrowed(command);
    }

    let mut out = String::with_capacity(len + 8);
    let mut copied = 0usize;
    for (segment_end, runs, last_word_byte) in segments {
        let moving: Vec<&(Range<usize>, usize)> = last_word_byte
            .map_or_else(Vec::new, |word_end| {
                runs.iter().filter(|(run, _)| run.end <= word_end).collect()
            });
        if moving.is_empty() {
            continue;
        }
        for (run, cut_end) in &moving {
            out.push_str(&command[copied..run.start]);
            copied = *cut_end;
        }
        // The whitespace that ended the segment separates it from the operator
        // that follows, so it goes back on AFTER the redirections land.
        let body = &command[copied..segment_end];
        let trimmed = body.trim_end_matches([' ', '\t']);
        out.push_str(trimmed);
        copied = segment_end;
        for (run, _) in &moving {
            if !out.is_empty() && !out.ends_with(char::is_whitespace) {
                out.push(' ');
            }
            out.push_str(&command[run.clone()]);
        }
        out.push_str(&body[trimmed.len()..]);
    }
    out.push_str(&command[copied..]);
    Cow::Owned(out)
}

/// Read one redirection, starting at its operator's first byte.
///
/// Returns the run's own byte range, and the byte the caller resumes copying
/// from if it cuts the run out: that swallows the whitespace separating the run
/// from what follows, so removing it does not leave a double space behind.
fn consume_redirection_run(bytes: &[u8], at: usize, len: usize) -> (Range<usize>, usize) {
    let mut start = at;
    let mut i = at;

    if bytes[i] == b'&' {
        // `&>` / `&>>`: the `&` belongs to the operator.
        i += 1;
    } else {
        // A file-descriptor prefix (`2>`, `10>>`) counts only when it opens the
        // word; digits glued to a command word are part of that word.
        let mut k = i;
        while k > 0 && bytes[k - 1].is_ascii_digit() {
            k -= 1;
        }
        if k < i && (k == 0 || bytes[k - 1].is_ascii_whitespace()) {
            start = k;
        }
    }

    let op_start = i;
    while i < len && matches!(bytes[i], b'>' | b'<') {
        i += 1;
    }
    // `>|` overrides noclobber; the `|` is the operator's, not a pipeline's.
    if i == op_start + 1 && bytes[op_start] == b'>' && i < len && bytes[i] == b'|' {
        i += 1;
    }

    let mut has_target = true;
    if i < len && bytes[i] == b'&' {
        // `>&1`, `<&3`, `>&-`: the duplicated descriptor is the target.
        let mut f = i + 1;
        if f < len && bytes[f] == b'-' {
            f += 1;
        } else {
            while f < len && bytes[f].is_ascii_digit() {
                f += 1;
            }
        }
        if f > i + 1 {
            i = f;
            has_target = false;
        } else {
            i += 1;
        }
    }

    if has_target {
        let mut t = i;
        while t < len && (bytes[t] == b' ' || bytes[t] == b'\t') {
            t += 1;
        }
        let word_end = consume_word_token(bytes, t, len);
        if word_end > t {
            i = word_end;
        }
    }

    let mut cut_end = i;
    while cut_end < len && (bytes[cut_end] == b' ' || bytes[cut_end] == b'\t') {
        cut_end += 1;
    }

    (start..i, cut_end)
}

/// Normalize a command by stripping absolute paths from common binaries.
///
/// Returns the original command unchanged if normalization fails (fail-open).
#[inline]
pub fn normalize_command(cmd: &str) -> Cow<'_, str> {
    // 0. Restore the word break an unquoted redirection already makes, so the
    //    command word is visible to every later step (tokenizer, path
    //    normalizers, pack patterns).
    let spaced = split_glued_redirections(cmd);
    // 0b. Park every redirection at the end of its own simple command, where the
    //     shell already puts it, so one parked mid-command no longer splits a
    //     command word from the arguments a pattern spells beside it.
    match move_redirections_to_segment_end(spaced.as_ref()) {
        Cow::Borrowed(_) => match spaced {
            Cow::Borrowed(_) => normalize_command_inner(cmd),
            Cow::Owned(split) => Cow::Owned(normalize_command_inner(&split).into_owned()),
        },
        Cow::Owned(moved) => Cow::Owned(normalize_command_inner(&moved).into_owned()),
    }
}

fn normalize_command_inner(cmd: &str) -> Cow<'_, str> {
    // 1. Strip wrappers (sudo, env, etc.)
    let stripped = crate::normalize::strip_wrapper_prefixes(cmd);

    match stripped.normalized {
        Cow::Borrowed(original_slice) => {
            // original_slice has lifetime 'a (from cmd)
            let dequoted = dequote_segment_command_words(original_slice);
            // dequoted has lifetime 'a.

            // 3. Strip paths (try both normalizers)
            match &dequoted {
                Cow::Borrowed(base) => {
                    apply_path_normalizers(base).map_or_else(|| dequoted, Cow::Owned)
                }
                Cow::Owned(base) => {
                    apply_path_normalizers(base).map_or_else(|| dequoted, Cow::Owned)
                }
            }
        }
        Cow::Owned(local_string) => {
            // local_string is local.
            let dequoted = dequote_segment_command_words(&local_string);
            // dequoted borrows from local_string.
            // We MUST return Owned.
            let base = dequoted.into_owned();

            // 3. Strip paths (try both normalizers)
            apply_path_normalizers(&base).map_or_else(|| Cow::Owned(base), Cow::Owned)
        }
    }
}

/// Strip leading backslash from the first command token.
///
/// This handles bash alias bypass: `\git` instead of `git`.
/// Also handles Windows-style commands like `\git.exe`.
fn strip_leading_backslash(command: &str) -> Option<(String, StrippedWrapper)> {
    let trimmed = command.trim_start();
    if !trimmed.starts_with('\\') {
        return None;
    }

    // Get the first token (command name)
    let rest = &trimmed[1..];
    if rest.is_empty() {
        return None;
    }

    // Find end of first token
    let first_word_end = rest.find(char::is_whitespace).unwrap_or(rest.len());

    let first_word = &rest[..first_word_end];

    // Only strip if the token looks like a valid command name
    // Allow alphanumeric, underscore, dash, and dot (for .exe extensions)
    if first_word.is_empty()
        || !first_word
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return None;
    }

    Some((
        rest.to_string(),
        StrippedWrapper {
            wrapper_type: "backslash",
            stripped_text: "\\".to_string(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sudo_simple() {
        let result = strip_wrapper_prefixes("sudo git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
        assert_eq!(result.stripped_wrappers.len(), 1);
        assert_eq!(result.stripped_wrappers[0].wrapper_type, "sudo");
    }

    #[test]
    fn test_sudo_with_options() {
        let result = strip_wrapper_prefixes("sudo -E -H git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_with_combined_options() {
        let result = strip_wrapper_prefixes("sudo -EH git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_with_user() {
        let result = strip_wrapper_prefixes("sudo -u root git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_unknown_flag_does_not_strip() {
        let result = strip_wrapper_prefixes("sudo -l rm -rf /");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_sudo_unknown_long_flag_does_not_strip() {
        let result = strip_wrapper_prefixes("sudo --list rm -rf /");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_tokenize_for_normalization_treats_newline_as_separator() {
        let cmd = "echo ok\nrm -rf /";
        let tokens = tokenize_for_normalization(cmd);

        let newline_token = tokens
            .iter()
            .find(|tok| tok.kind == NormalizeTokenKind::Separator && tok.text(cmd) == Some("\n"));
        assert!(newline_token.is_some(), "Expected newline separator token");
    }

    #[test]
    fn test_not_sudo_prefix() {
        let result = strip_wrapper_prefixes("sudoku play");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_env_simple() {
        let result = strip_wrapper_prefixes("env git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_env_with_assignment() {
        let result = strip_wrapper_prefixes("env GIT_DIR=.git git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_env_with_quoted_assignment() {
        let result = strip_wrapper_prefixes("env FOO=\"a b\" git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_env_assignment_with_backticks_preserved() {
        let result = strip_wrapper_prefixes("env FOO=`rm -rf /` git status");
        assert!(
            result.normalized.contains("rm -rf /"),
            "assignment with inline code should remain visible"
        );
    }

    #[test]
    fn test_env_assignment_with_single_quoted_backticks_skipped() {
        let result = strip_wrapper_prefixes("env FOO='`rm -rf /`' git status");
        assert_eq!(result.normalized, "git status");
    }

    #[test]
    fn test_env_alone() {
        let result = strip_wrapper_prefixes("env");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_wrapper() {
        let result = strip_wrapper_prefixes("command git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_command_wrapper_with_path() {
        let result = strip_wrapper_prefixes("/usr/bin/command git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_command_v_not_wrapper() {
        let result = strip_wrapper_prefixes("command -v git");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_v_with_path_not_wrapper() {
        let result = strip_wrapper_prefixes("/usr/bin/command -v git");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_pv_not_wrapper() {
        let result = strip_wrapper_prefixes("command -pv git");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_p_wrapper() {
        let result = strip_wrapper_prefixes("command -p git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_command_unknown_flag_does_not_strip() {
        let result = strip_wrapper_prefixes("command -x git reset --hard");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_unknown_long_flag_does_not_strip() {
        let result = strip_wrapper_prefixes("command --foo git reset --hard");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_backslash_git() {
        let result = strip_wrapper_prefixes("\\git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_env_chain() {
        let result = strip_wrapper_prefixes("sudo env GIT_DIR=.git git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
        assert_eq!(result.stripped_wrappers.len(), 2);
    }

    #[test]
    fn test_env_split_string_handling() {
        // env -S treats the argument as a script/command line.
        // We parse the -S argument to extract the command and strip the wrapper.
        let result = strip_wrapper_prefixes("env -S \"git reset --hard\"");

        // Should be normalized
        assert!(result.was_normalized());
        assert_eq!(result.normalized, "git reset --hard");
        assert_eq!(result.stripped_wrappers.len(), 1);
        assert_eq!(result.stripped_wrappers[0].wrapper_type, "env");
        assert_eq!(
            result.stripped_wrappers[0].stripped_text,
            "env -S \"git reset --hard\""
        );
    }

    #[test]
    fn test_env_split_string_long_option() {
        let result = strip_wrapper_prefixes("env --split-string \"git reset --hard\"");
        assert!(result.was_normalized());
        assert_eq!(result.normalized, "git reset --hard");
        assert_eq!(result.stripped_wrappers[0].wrapper_type, "env");
    }

    #[test]
    fn test_env_chdir_long_option() {
        let result = strip_wrapper_prefixes("env --chdir /tmp git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_env_unknown_long_option_not_stripped() {
        let result = strip_wrapper_prefixes("env --not-a-real-flag git reset --hard");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_empty_command() {
        let result = strip_wrapper_prefixes("");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_no_wrappers() {
        let result = strip_wrapper_prefixes("git status");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_sudo_with_shell_flag() {
        // -s runs user's shell; command is passed via -c
        let result = strip_wrapper_prefixes("sudo -s git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
        assert_eq!(result.stripped_wrappers[0].wrapper_type, "sudo");
    }

    #[test]
    fn test_sudo_shell_alone() {
        // sudo -s alone (no command) should not be stripped
        let result = strip_wrapper_prefixes("sudo -s");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_sudo_with_bell_flag() {
        // -B rings bell on password prompt
        let result = strip_wrapper_prefixes("sudo -B git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_with_chdir() {
        // -D changes directory before running command
        let result = strip_wrapper_prefixes("sudo -D /tmp git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_with_type() {
        // -t changes SELinux type
        let result = strip_wrapper_prefixes("sudo -t unconfined_t git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_combined_shell_flags() {
        // Combined flags including -s
        let result = strip_wrapper_prefixes("sudo -EBs git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_dequote_preserves_rm_quoted_paths() {
        assert_eq!(
            dequote_segment_command_words(r#"rm -rf "/tmp/foo""#).as_ref(),
            r#"rm -rf "/tmp/foo""#
        );
        assert_eq!(
            dequote_segment_command_words(r#"rm -r -f "$TMPDIR/foo""#).as_ref(),
            r#"rm -r -f "$TMPDIR/foo""#
        );
    }

    #[test]
    fn test_dequote_normalizes_git_quoted_subcommand() {
        assert_eq!(
            dequote_segment_command_words(r#"git "reset" --hard"#).as_ref(),
            "git reset --hard"
        );
    }

    #[test]
    fn test_mismatched_quotes_not_unquoted() {
        // Mismatched quotes should NOT be unquoted
        assert_eq!(
            normalize_command_word_token(r#""hello'"#),
            None // No normalization should occur
        );
        assert_eq!(
            normalize_command_word_token(r#"'hello""#),
            None // No normalization should occur
        );
        // But matching quotes should still work
        assert_eq!(
            normalize_command_word_token(r#""hello""#),
            Some("hello".to_string())
        );
        assert_eq!(
            normalize_command_word_token("'hello'"),
            Some("hello".to_string())
        );
    }
}

#[cfg(test)]
mod windows_exe_tests {
    use super::*;

    #[test]
    fn test_backslash_exe_normalization() {
        let result = strip_wrapper_prefixes(r"\git.exe reset --hard");
        eprintln!("After strip_wrapper_prefixes: {:?}", result.normalized);
        assert!(result.was_normalized(), "backslash should be stripped");
        assert_eq!(result.normalized, "git.exe reset --hard");
    }

    #[test]
    fn test_exe_stripping_in_normalize_command() {
        let result = normalize_command(r"\git.exe reset --hard");
        eprintln!("Normalized result: {:?}", result.as_ref());
        assert_eq!(result.as_ref(), "git reset --hard");
    }
}

#[test]
fn test_windows_path_with_spaces_tokenization() {
    // This path has spaces - see how tokenization handles it
    let cmd = "C:/Program Files/Git/bin/git.exe reset --hard";
    let tokens = tokenize_for_normalization(cmd);
    eprintln!("Tokens:");
    for (i, tok) in tokens.iter().enumerate() {
        eprintln!("  {}: {:?} = {:?}", i, tok.kind, tok.text(cmd));
    }

    // The second token should contain git.exe
    let has_git_exe = tokens.iter().any(|t| {
        t.kind == NormalizeTokenKind::Word
            && t.text(cmd).unwrap_or("").to_lowercase().contains("git.exe")
    });
    eprintln!("Has git.exe: {has_git_exe}");
}

#[test]
fn test_quoted_windows_path_normalization() {
    // Use git status instead of git reset to avoid triggering DCG in tests
    let cmd = r#""C:/Program Files/Git/bin/git.exe" status"#;
    eprintln!("Input: {cmd}");

    let result = normalize_command(cmd);
    eprintln!("Normalized: {:?}", result.as_ref());

    let tokens = tokenize_for_normalization(&result);
    eprintln!("Tokens after normalization:");
    for (i, tok) in tokens.iter().enumerate() {
        eprintln!("  {}: {:?} = {:?}", i, tok.kind, tok.text(&result));
    }
}

#[test]
fn test_keyword_matching_in_windows_path() {
    use crate::packs::pack_aware_quick_reject;

    let keywords: Vec<&str> = vec!["git", "rm"];

    // Test if quick_reject correctly identifies these as git commands
    // Using "git status" instead of destructive commands
    let cmds = [
        r#""C:/Program Files/Git/bin/git" status"#,
        r#""C:/Program Files/Git/bin/git.exe" status"#, // with .exe
        "C:/Git/bin/git status",
        "git status",
    ];

    for cmd in cmds {
        // First check what classify_command returns
        let normalized = normalize_command(cmd);
        let spans = crate::context::classify_command(&normalized);
        eprintln!("{cmd:?} -> normalized: {:?}", normalized.as_ref());
        eprintln!("  executable spans:");
        for span in spans.executable_spans() {
            eprintln!("    {:?}", span.text(&normalized));
        }

        let rejected = pack_aware_quick_reject(cmd, &keywords);
        eprintln!("  quick_reject={rejected}");
        // If rejected is FALSE, keywords were found (should NOT be quick-rejected)
        assert!(!rejected, "Command should NOT be quick-rejected: {cmd}");
    }
}

#[test]
fn test_internal_backslash_normalization() {
    // g\it should normalize to git (bash treats backslash as escape for regular chars)
    let result = normalize_command_word_token(r"g\it");
    assert_eq!(
        result,
        Some("git".to_string()),
        "g\\it should normalize to git"
    );

    // Multiple internal backslashes
    let result = normalize_command_word_token(r"g\i\t");
    assert_eq!(
        result,
        Some("git".to_string()),
        "g\\i\\t should normalize to git"
    );

    // Full command normalization
    let result = normalize_command(r"g\it reset --hard");
    assert_eq!(
        result.as_ref(),
        "git reset --hard",
        "g\\it command should normalize"
    );
}

#[test]
fn test_mixed_quoting_normalization() {
    // g'i't should normalize to git (bash concatenates adjacent quoted/unquoted sections)
    let result = normalize_command_word_token("g'i't");
    assert_eq!(
        result,
        Some("git".to_string()),
        "g'i't should normalize to git"
    );

    // Double quotes
    let result = normalize_command_word_token(r#"g"i"t"#);
    assert_eq!(
        result,
        Some("git".to_string()),
        r#"g"i"t should normalize to git"#
    );

    // Full command normalization
    let result = normalize_command("g'i't reset --hard");
    assert_eq!(
        result.as_ref(),
        "git reset --hard",
        "g'i't command should normalize"
    );
}

#[cfg(test)]
mod redirection_position_tests {
    use super::{move_redirections_to_segment_end, normalize_command};
    use std::borrow::Cow;

    /// The rows measured on `.agent-config-y1h6c`: a redirection parked between
    /// the command word and its arguments, in every spelling the shell accepts.
    #[test]
    fn interposed_redirection_moves_to_the_end_of_its_command() {
        for (input, expected) in [
            ("rm >/dev/null -rf /", "rm -rf / >/dev/null"),
            ("rm > /dev/null -rf /", "rm -rf / > /dev/null"),
            ("rm >>build.log -rf /", "rm -rf / >>build.log"),
            ("rm </dev/null -rf /", "rm -rf / </dev/null"),
            ("rm 2>/dev/null -rf /", "rm -rf / 2>/dev/null"),
            ("rm 2>&1 -rf /", "rm -rf / 2>&1"),
            ("rm &>/dev/null -rf /", "rm -rf / &>/dev/null"),
            (">/dev/null rm -rf /", "rm -rf / >/dev/null"),
            ("git reset >/dev/null --hard", "git reset --hard >/dev/null"),
        ] {
            assert_eq!(
                move_redirections_to_segment_end(input).as_ref(),
                expected,
                "{input}"
            );
        }
    }

    /// A redirection may not cross out of the simple command it belongs to: the
    /// operator applies to one program, and moving it past a list or pipeline
    /// operator would attach it to a different one.
    #[test]
    fn a_redirection_stays_inside_its_own_simple_command() {
        for (input, expected) in [
            ("ls -la; rm >/dev/null -rf /", "ls -la; rm -rf / >/dev/null"),
            (
                "echo hi | xargs rm >/dev/null -rf /",
                "echo hi | xargs rm -rf / >/dev/null",
            ),
            (
                "rm >/dev/null -rf / && echo done",
                "rm -rf / >/dev/null && echo done",
            ),
            ("(rm >/dev/null -rf /)", "(rm -rf / >/dev/null)"),
            (
                "rm >/dev/null -rf /\necho done",
                "rm -rf / >/dev/null\necho done",
            ),
        ] {
            assert_eq!(
                move_redirections_to_segment_end(input).as_ref(),
                expected,
                "{input}"
            );
        }
    }

    /// Moving is not deleting. Patterns that match ON a redirection --
    /// `sqlite3 <db> < dump.sql` is one -- look for it at the end of the
    /// command, which is where it already is, so those commands come back
    /// borrowed and byte-identical.
    #[test]
    fn a_redirection_that_already_ends_its_command_is_left_alone() {
        for input in [
            "rm -rf / >/dev/null",
            "sqlite3 mydb.db < dump.sql",
            "ls -la > out.txt",
            "git status >/dev/null 2>&1",
            "npm run build 2>&1 | tee build.log",
            "make > build.log; echo done",
        ] {
            let moved = move_redirections_to_segment_end(input);
            assert!(
                matches!(moved, Cow::Borrowed(_)),
                "{input} should not be rewritten"
            );
            assert_eq!(moved.as_ref(), input, "{input}");
        }
    }

    /// A heredoc body is data the masker reads verbatim, and its tokenization
    /// is the masker's to own. Moving a word out of a body would rewrite what
    /// the receiver is handed, so a command carrying `<<` or `<<<` is left
    /// exactly as written -- including one whose body contains a redirection.
    #[test]
    fn a_heredoc_command_is_left_exactly_as_written() {
        for input in [
            "cat <<EOF > /tmp/x.txt\nhello\nEOF",
            "cat <<'EOF'\nrm >/dev/null -rf /\nEOF",
            "bash <<< 'rm >/dev/null -rf /'",
        ] {
            let moved = move_redirections_to_segment_end(input);
            assert!(
                matches!(moved, Cow::Borrowed(_)),
                "{input:?} should not be rewritten"
            );
        }
    }

    /// `>` and `<` inside quotes or behind a backslash are data, not operators.
    #[test]
    fn quoted_and_escaped_angle_brackets_are_not_operators() {
        for input in [
            r#"echo "a > b" && echo c"#,
            "echo 'x < y' && echo c",
            r"echo a \> b && echo c",
        ] {
            let moved = move_redirections_to_segment_end(input);
            assert!(
                matches!(moved, Cow::Borrowed(_)),
                "{input:?} should not be rewritten"
            );
        }
    }

    /// The whole point: after normalization the pack patterns see a command
    /// word sitting next to the arguments they spell.
    #[test]
    fn normalize_command_parks_the_redirection_at_the_end() {
        assert_eq!(
            normalize_command("rm >/dev/null -rf /").as_ref(),
            "rm -rf / >/dev/null"
        );
        // Glued spelling first (.agent-config-6yt2i), then the move.
        assert_eq!(
            normalize_command("rm>/dev/null -rf /").as_ref(),
            "rm -rf / >/dev/null"
        );
        assert_eq!(
            normalize_command("git>/dev/null reset --hard").as_ref(),
            "git reset --hard >/dev/null"
        );
    }
}
