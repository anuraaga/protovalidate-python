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

use crate::rules::CompileError;
use crate::rules::eval::EvalError;

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
            Self::Unexpected(message) => write!(f, "unexpected error: {message}"),
        }
    }
}

impl std::error::Error for Error {}

/// A failure of validation itself, before it is typed by violation.
pub(crate) enum Internal {
    Compilation(String),
    Evaluation(String),
    Argument(String),
    Unexpected(String),
}

impl From<CompileError> for Internal {
    fn from(error: CompileError) -> Self {
        Self::Compilation(error.0)
    }
}

impl From<EvalError> for Internal {
    fn from(error: EvalError) -> Self {
        match error {
            EvalError::Runtime(message) => Self::Evaluation(message),
            #[cfg(feature = "cel")]
            EvalError::Argument(message) => Self::Argument(message),
            EvalError::Unexpected(message) => Self::Unexpected(message),
        }
    }
}

impl From<Internal> for Error {
    fn from(error: Internal) -> Self {
        match error {
            Internal::Compilation(message) => Self::Compilation(message),
            Internal::Evaluation(message) => Self::Evaluation(message),
            Internal::Argument(message) => Self::Argument(message),
            Internal::Unexpected(message) => Self::Unexpected(message),
        }
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
