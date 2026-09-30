// Copyright (c) 2023-2026 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The regular expression engine behind `pattern` rules and the well-known
//! string formats. With the `cel` feature it is RE2, through cel-cpp, so a
//! native `pattern` rule and a `matches()` call in a custom rule accept the
//! same syntax and agree on every input. Without it, `regex-lite` stands
//! in. Like RE2 its `\d`, `\w`, `\s` and `\b` are ASCII, but it differs
//! in places: `(?i)` folds ASCII only, `\p{...}` classes and `\Q...\E`
//! are not supported, and repeat counts are not capped at 1000.

#[cfg(feature = "cel")]
type Inner = protovalidate_deps::Regex;
#[cfg(not(feature = "cel"))]
type Inner = regex_lite::Regex;

/// A compiled pattern.
#[derive(Debug)]
pub(crate) struct Regex(Inner);

impl Regex {
    /// Compiles `pattern`, or returns the engine's message for one it
    /// rejects.
    pub(crate) fn new(pattern: &str) -> Result<Self, String> {
        Inner::new(pattern)
            .map(Self)
            .map_err(|error| error.to_string())
    }

    /// Whether `text` contains a match.
    pub(crate) fn is_match(&self, text: &str) -> bool {
        self.0.is_match(text)
    }
}
