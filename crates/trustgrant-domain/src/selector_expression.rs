use std::fmt;

use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{MAX_SELECTOR_EXPRESSION_BYTES, ensure_string_limit};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectorPredicate {
    Equals,
    StartsWith,
    EndsWith,
    Contains,
}

impl SelectorPredicate {
    fn parse(value: &str) -> Result<Self, TrustGrantError> {
        match value {
            "equals" => Ok(Self::Equals),
            "startsWith" => Ok(Self::StartsWith),
            "endsWith" => Ok(Self::EndsWith),
            "contains" => Ok(Self::Contains),
            _ => Err(TrustGrantError::UnsupportedSelectorExpressionPredicate(
                value.to_owned(),
            )),
        }
    }
}

impl fmt::Display for SelectorPredicate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Equals => "equals",
            Self::StartsWith => "startsWith",
            Self::EndsWith => "endsWith",
            Self::Contains => "contains",
        };

        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SelectorExpression {
    predicate: SelectorPredicate,
    argument: Box<str>,
}

impl SelectorExpression {
    /// Parses one v0 selector expression.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the expression is empty, malformed, or
    /// uses an unsupported predicate.
    pub fn parse(value: &str) -> Result<Self, TrustGrantError> {
        let value = normalize_non_empty_expression(value)?;
        ensure_string_limit("selector.expression", value, MAX_SELECTOR_EXPRESSION_BYTES)?;
        let open_paren = value
            .find('(')
            .ok_or(TrustGrantError::InvalidSelectorExpressionSyntax)?;

        if !value.ends_with(')') {
            return Err(TrustGrantError::InvalidSelectorExpressionSyntax);
        }

        let predicate = SelectorPredicate::parse(value[..open_paren].trim())?;
        let (_, after_open) = value.split_at(open_paren);
        let quoted_argument = after_open
            .strip_prefix('(')
            .and_then(|inner| inner.strip_suffix(')'))
            .ok_or(TrustGrantError::InvalidSelectorExpressionSyntax)?
            .trim();
        let argument = parse_quoted_argument(quoted_argument)?;

        Ok(Self {
            predicate,
            argument: argument.into_boxed_str(),
        })
    }

    #[must_use = "selector expressions participate in evaluation matching"]
    pub const fn predicate(&self) -> SelectorPredicate {
        self.predicate
    }

    #[must_use = "selector expression argument participates in evaluation matching"]
    pub fn argument(&self) -> &str {
        &self.argument
    }

    #[must_use = "selector expression match result determines scope evaluation"]
    pub fn matches(&self, candidate: &str) -> bool {
        match self.predicate {
            SelectorPredicate::Equals => candidate == self.argument(),
            SelectorPredicate::StartsWith => candidate.starts_with(self.argument()),
            SelectorPredicate::EndsWith => candidate.ends_with(self.argument()),
            SelectorPredicate::Contains => candidate.contains(self.argument()),
        }
    }
}

impl fmt::Display for SelectorExpression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}(\"", self.predicate())?;

        for character in self.argument().chars() {
            match character {
                '\\' => formatter.write_str(r#"\\"#)?,
                '"' => formatter.write_str("\\\"")?,
                '\n' => formatter.write_str(r#"\n"#)?,
                '\r' => formatter.write_str(r#"\r"#)?,
                '\t' => formatter.write_str(r#"\t"#)?,
                other => write!(formatter, "{other}")?,
            }
        }

        formatter.write_str("\")")
    }
}

fn normalize_non_empty_expression(value: &str) -> Result<&str, TrustGrantError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(TrustGrantError::EmptyStringField("selector.expression"));
    }

    Ok(trimmed)
}

fn parse_quoted_argument(value: &str) -> Result<String, TrustGrantError> {
    let inner = value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .ok_or(TrustGrantError::InvalidSelectorExpressionSyntax)?;
    let mut chars = inner.chars();
    let mut parsed = String::new();

    while let Some(character) = chars.next() {
        if character == '"' {
            return Err(TrustGrantError::InvalidSelectorExpressionSyntax);
        }

        if character == '\\' {
            let escaped = chars
                .next()
                .ok_or(TrustGrantError::InvalidSelectorExpressionSyntax)?;
            let unescaped = match escaped {
                '\\' => '\\',
                '"' => '"',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                _ => return Err(TrustGrantError::InvalidSelectorExpressionSyntax),
            };
            parsed.push(unescaped);
            continue;
        }

        if character.is_control() {
            return Err(TrustGrantError::InvalidSelectorExpressionSyntax);
        }

        parsed.push(character);
    }

    ensure_string_limit(
        "selector.expression",
        &parsed,
        MAX_SELECTOR_EXPRESSION_BYTES,
    )?;

    Ok(parsed)
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::{SelectorExpression, SelectorPredicate};
    use trustgrant_error::TrustGrantError;

    #[test]
    fn selector_expression_parses_supported_predicates() {
        let expression = SelectorExpression::parse(r#"startsWith("vip_")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));

        assert_eq!(expression.predicate(), SelectorPredicate::StartsWith);
        assert_eq!(expression.argument(), "vip_");
        assert!(expression.matches("vip_gold"));
        assert!(!expression.matches("gold_vip"));
    }

    #[test]
    fn selector_expression_supports_quoted_escape_sequences() {
        let expression = SelectorExpression::parse(r#"contains("event\"drop")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));

        assert!(expression.matches("vip_event\"drop_box"));
    }

    #[test]
    fn selector_expression_rejects_unknown_predicates() {
        assert_eq!(
            SelectorExpression::parse(r#"regex("^vip")"#),
            Err(TrustGrantError::UnsupportedSelectorExpressionPredicate(
                "regex".to_owned(),
            ))
        );
    }

    #[test]
    fn selector_expression_rejects_non_string_arguments() {
        assert_eq!(
            SelectorExpression::parse("equals(123)"),
            Err(TrustGrantError::InvalidSelectorExpressionSyntax)
        );
    }

    #[test]
    fn equals_predicate_matches_exact_string() {
        let expression = SelectorExpression::parse(r#"equals("foo")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert!(expression.matches("foo"));
    }

    #[test]
    fn equals_predicate_rejects_different_string() {
        let expression = SelectorExpression::parse(r#"equals("foo")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert!(!expression.matches("bar"));
    }

    #[test]
    fn starts_with_predicate_matches_prefix() {
        let expression = SelectorExpression::parse(r#"startsWith("weapon_")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert!(expression.matches("weapon_epic"));
    }

    #[test]
    fn starts_with_predicate_rejects_non_prefix() {
        let expression = SelectorExpression::parse(r#"startsWith("weapon_")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert!(!expression.matches("armor_epic"));
    }

    #[test]
    fn ends_with_predicate_matches_suffix() {
        let expression = SelectorExpression::parse(r#"endsWith("_epic")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert!(expression.matches("weapon_epic"));
    }

    #[test]
    fn ends_with_predicate_rejects_non_suffix() {
        let expression = SelectorExpression::parse(r#"endsWith("_epic")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert!(!expression.matches("weapon_rare"));
    }

    #[test]
    fn contains_predicate_matches_substring() {
        let expression = SelectorExpression::parse(r#"contains("epic")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert!(expression.matches("weapon_epic"));
    }

    #[test]
    fn contains_predicate_rejects_non_substring() {
        let expression = SelectorExpression::parse(r#"contains("epic")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert!(!expression.matches("weapon_rare"));
    }

    #[test]
    fn selector_expression_display_format() {
        let expression = SelectorExpression::parse(r#"equals("foo")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert_eq!(format!("{expression}"), r#"equals("foo")"#);
    }

    #[test]
    fn selector_expression_display_escapes_special_chars() {
        let expression = SelectorExpression::parse(r#"contains("a\\b\"c\n")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert_eq!(format!("{expression}"), r#"contains("a\\b\"c\n")"#);
    }

    // ── Lines 32-33: Display for EndsWith and Contains predicates ───────

    #[test]
    fn selector_expression_display_ends_with_predicate() {
        let expression = SelectorExpression::parse(r#"endsWith("_epic")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert_eq!(format!("{expression}"), r#"endsWith("_epic")"#);
    }

    #[test]
    fn selector_expression_display_contains_predicate() {
        let expression = SelectorExpression::parse(r#"contains("epic")"#)
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert_eq!(format!("{expression}"), r#"contains("epic")"#);
    }

    // ── Lines 110-111: Display for \r and \t escapes ───────────────────

    #[test]
    fn selector_expression_display_escapes_cr_and_tab() {
        let expression = SelectorExpression::parse("contains(\"a\\rb\\tc\")")
            .unwrap_or_else(|error| panic!("expression should parse: {error}"));
        assert_eq!(format!("{expression}"), "contains(\"a\\rb\\tc\")");
    }

    // ── Line 32: Display for StartsWith ─────────────────────────────────

    #[test]
    fn selector_predicate_display_starts_with() {
        assert_eq!(SelectorPredicate::StartsWith.to_string(), "startsWith");
    }

    // ── Line 62: missing closing paren ──────────────────────────────────

    #[test]
    fn selector_expression_rejects_missing_closing_paren() {
        let result = SelectorExpression::parse(r#"equals("foo""#);
        assert_eq!(
            result,
            Err(TrustGrantError::InvalidSelectorExpressionSyntax)
        );
    }

    // ── Line 124: empty trimmed expression ──────────────────────────────

    #[test]
    fn selector_expression_rejects_empty_string() {
        let result = SelectorExpression::parse("   ");
        assert_eq!(
            result,
            Err(TrustGrantError::EmptyStringField("selector.expression"))
        );
    }

    // ── Line 140: inner unquoted double quote ───────────────────────────

    #[test]
    fn selector_expression_rejects_unescaped_inner_quote() {
        let result = SelectorExpression::parse(r#"equals("foo"bar")"#);
        assert_eq!(
            result,
            Err(TrustGrantError::InvalidSelectorExpressionSyntax)
        );
    }

    // ── Lines 151-153: unrecognized escape after backslash ──────────────

    #[test]
    fn selector_expression_rejects_unrecognized_escape() {
        let result = SelectorExpression::parse(r#"equals("foo\abar")"#);
        assert_eq!(
            result,
            Err(TrustGrantError::InvalidSelectorExpressionSyntax)
        );
    }

    // ── Line 160: control character in parsed argument ──────────────────

    #[test]
    fn selector_expression_rejects_control_character_in_argument() {
        let result = SelectorExpression::parse("equals(\"foo\u{0007}bar\")");
        assert_eq!(
            result,
            Err(TrustGrantError::InvalidSelectorExpressionSyntax)
        );
    }
}
