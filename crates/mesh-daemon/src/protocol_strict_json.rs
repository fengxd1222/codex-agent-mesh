//! Strict JSON parsing helpers for protocol frames.

use std::collections::HashSet;

use serde_json::Value;

/// Maximum number of nested JSON arrays/objects admitted at the wire boundary.
///
/// The duplicate-key scanner runs before serde/jsonschema, so it must impose its
/// own small recursion ceiling rather than relying on a downstream parser.
pub const MAX_JSON_DEPTH: usize = 128;

#[derive(Debug)]
pub struct StrictJsonError;

struct Scanner<'a> {
    source: &'a str,
    offset: usize,
}

impl Scanner<'_> {
    fn whitespace(&mut self) {
        while self
            .source
            .as_bytes()
            .get(self.offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.offset += 1;
        }
    }

    fn string(&mut self) -> Result<String, StrictJsonError> {
        let bytes = self.source.as_bytes();
        let start = self.offset;
        if bytes.get(self.offset) != Some(&b'"') {
            return Err(StrictJsonError);
        }
        self.offset += 1;
        while let Some(byte) = bytes.get(self.offset) {
            match byte {
                b'\\' => self.offset = self.offset.checked_add(2).ok_or(StrictJsonError)?,
                b'"' => {
                    self.offset += 1;
                    return serde_json::from_str(&self.source[start..self.offset])
                        .map_err(|_| StrictJsonError);
                }
                _ => self.offset += 1,
            }
        }
        Err(StrictJsonError)
    }

    fn value(&mut self, container_depth: usize) -> Result<(), StrictJsonError> {
        self.whitespace();
        match self.source.as_bytes().get(self.offset) {
            Some(b'{') => {
                if container_depth >= MAX_JSON_DEPTH {
                    return Err(StrictJsonError);
                }
                self.offset += 1;
                let mut keys = HashSet::new();
                self.whitespace();
                if self.source.as_bytes().get(self.offset) == Some(&b'}') {
                    self.offset += 1;
                    return Ok(());
                }
                loop {
                    self.whitespace();
                    if !keys.insert(self.string()?) {
                        return Err(StrictJsonError);
                    }
                    self.whitespace();
                    if self.source.as_bytes().get(self.offset) != Some(&b':') {
                        return Err(StrictJsonError);
                    }
                    self.offset += 1;
                    self.value(container_depth + 1)?;
                    self.whitespace();
                    match self.source.as_bytes().get(self.offset) {
                        Some(b'}') => {
                            self.offset += 1;
                            return Ok(());
                        }
                        Some(b',') => self.offset += 1,
                        _ => return Err(StrictJsonError),
                    }
                }
            }
            Some(b'[') => {
                if container_depth >= MAX_JSON_DEPTH {
                    return Err(StrictJsonError);
                }
                self.offset += 1;
                self.whitespace();
                if self.source.as_bytes().get(self.offset) == Some(&b']') {
                    self.offset += 1;
                    return Ok(());
                }
                loop {
                    self.value(container_depth + 1)?;
                    self.whitespace();
                    match self.source.as_bytes().get(self.offset) {
                        Some(b']') => {
                            self.offset += 1;
                            return Ok(());
                        }
                        Some(b',') => self.offset += 1,
                        _ => return Err(StrictJsonError),
                    }
                }
            }
            Some(b'"') => self.string().map(|_| ()),
            Some(_) => {
                let start = self.offset;
                while self.source.as_bytes().get(self.offset).is_some_and(|byte| {
                    !byte.is_ascii_whitespace() && !matches!(byte, b',' | b']' | b'}')
                }) {
                    self.offset += 1;
                }
                (start != self.offset).then_some(()).ok_or(StrictJsonError)
            }
            None => Err(StrictJsonError),
        }
    }
}

/// Parses a UTF-8 JSON source while rejecting duplicate keys at every depth.
///
/// # Errors
///
/// Returns `StrictJsonError` for malformed JSON, trailing data, or a duplicate
/// object key at any nesting depth.
pub fn parse_strict_json(source: &str) -> Result<Value, StrictJsonError> {
    let mut scanner = Scanner { source, offset: 0 };
    scanner.value(0)?;
    scanner.whitespace();
    if scanner.offset != source.len() {
        return Err(StrictJsonError);
    }
    serde_json::from_str(source).map_err(|_| StrictJsonError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bounded_nesting_below_the_hard_ceiling() {
        let source = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH - 1),
            "]".repeat(MAX_JSON_DEPTH - 1)
        );
        assert!(parse_strict_json(&source).is_ok());
    }

    #[test]
    fn rejects_deep_arrays_and_objects_before_stack_exhaustion() {
        let arrays = format!("{}0{}", "[".repeat(10_000), "]".repeat(10_000));
        assert!(parse_strict_json(&arrays).is_err());

        let objects = format!("{}0{}", "{\"x\":".repeat(10_000), "}".repeat(10_000));
        assert!(parse_strict_json(&objects).is_err());
    }
}
