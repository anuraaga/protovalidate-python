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

use std::fmt;

use crate::protobuf::ReadError;

/// A descriptor that could not be registered.
#[derive(Debug)]
pub struct DescriptorError {
    message: String,
}

impl DescriptorError {
    pub(crate) fn new(message: String) -> Self {
        Self { message }
    }
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DescriptorError {}

/// A failed validation.
///
/// [`Validation`](Self::Validation) means the message broke its rules and
/// carries the violations, while every other variant means validation itself
/// did not run to completion.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The message broke one or more of its rules.
    Validation(ValidationError),
    /// Validation rules could not be compiled.
    Compilation(String),
    /// A rule failed while being evaluated.
    Evaluation(String),
    /// Bad input: an unparsable payload or an unknown type.
    Argument(String),
    /// The runtime could not read the message: its own error, boxed, which
    /// the caller that owns the runtime can downcast back.
    Read(ReadError),
    /// A failure that fits no other category.
    Unexpected(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(error) => error.fmt(f),
            Self::Compilation(message) => write!(f, "compilation error: {message}"),
            Self::Evaluation(message) => write!(f, "evaluation error: {message}"),
            Self::Argument(message) => write!(f, "invalid argument: {message}"),
            Self::Read(error) => write!(f, "could not read message: {error}"),
            Self::Unexpected(message) => write!(f, "unexpected error: {message}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error.inner()),
            _ => None,
        }
    }
}

impl From<ReadError> for Error {
    fn from(error: ReadError) -> Self {
        Self::Read(error)
    }
}

/// One or more rule violations, carried by [`Error::Validation`] as a
/// serialized `buf.validate.Violations`.
pub struct ValidationError {
    violations: Vec<u8>,
}

impl ValidationError {
    pub(crate) fn new(violations: Vec<u8>) -> Self {
        Self { violations }
    }

    /// The violations, as a serialized `buf.validate.Violations`.
    #[must_use]
    pub fn violations(&self) -> &[u8] {
        &self.violations
    }
}

impl std::error::Error for ValidationError {}

impl fmt::Debug for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidationError")
            .field("violations_len", &self.violations.len())
            .finish()
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("validation failed")
    }
}
