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

//! How the validator reads messages, independently of the runtime that
//! holds them.
//!
//! A [`Runtime`] names the views a runtime gives out for a message, a
//! repeated field and a map, and those views implement [`Message`],
//! [`List`] and [`Map`]. Validation is generic over the runtime, so a
//! message is read in place -- string and bytes values borrow from it,
//! sub-messages are further views -- and nothing is copied into an
//! intermediate representation. Only when a CEL rule binds a message, list
//! or map to `this` is the message it is read from encoded, through
//! [`Message::encode`], for the CEL runtime to parse.
//!
//! A runtime plugs in by implementing these and calling
//! [`Validator::validate_message`](crate::Validator::validate_message).
//! Each field the validator asks for comes described as a [`Field`],
//! resolved from the descriptors registered with it, so a runtime needs no
//! descriptors of its own: how a field is stored is all that is left to it.
//! A read that fails -- a runtime over another language raising, say -- is
//! a [`ReadError`]; it ends the validation and reaches the caller as
//! [`Error::Read`](crate::Error::Read).

use std::borrow::Cow;
use std::fmt;
use std::ops::ControlFlow;

mod field;

pub use field::{Field, Kind, Scalar, Singular};

/// The runtime's own error, boxed.
type BoxedError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Why a runtime could not read a message: its own error, which the caller
/// that owns the runtime can downcast back. Any error type converts into
/// one, so a runtime's `?` does the wrapping.
///
/// The handle is one word -- the error is boxed twice for that -- so that a
/// fallible read of a small value still returns in registers, and the reads
/// the walk makes at every field cost what infallible ones would.
pub struct ReadError(Box<BoxedError>);

impl ReadError {
    /// Wraps a runtime's error.
    ///
    /// Cold and out of line, so that the `?` at every read of a message
    /// stays a branch and a call, and the readers stay small enough to be
    /// inlined into the walk.
    #[cold]
    #[inline(never)]
    #[must_use]
    pub fn new(error: impl Into<BoxedError>) -> Self {
        Self(Box::new(error.into()))
    }

    /// The runtime's error.
    #[must_use]
    pub fn inner(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        &**self.0
    }

    /// The runtime's error, to downcast back to its type.
    #[must_use]
    pub fn into_inner(self) -> BoxedError {
        *self.0
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<E> for ReadError {
    fn from(error: E) -> Self {
        Self::new(error)
    }
}

impl fmt::Debug for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A Protobuf runtime, through the views it gives out.
pub trait Runtime: Sized {
    /// A message, read in place.
    type Message<'a>: Message<Self>;
    /// A repeated field's elements.
    type List<'a>: List<Self>;
    /// A map field's entries.
    type Map<'a>: Map<Self>;
}

/// A field's value, borrowed from the message that holds it.
///
/// Integers are widened to the CEL types they become, and floats to
/// `double`; that is all the rules distinguish.
pub enum Val<'a, R: Runtime> {
    Bool(bool),
    Int(i64),
    Uint(u64),
    Double(f64),
    Enum(i32),
    String(Cow<'a, str>),
    Bytes(Cow<'a, [u8]>),
    Message(R::Message<'a>),
    List(R::List<'a>),
    Map(R::Map<'a>),
}

/// A map key.
pub enum Key<'a> {
    Bool(bool),
    Int(i64),
    Uint(u64),
    String(Cow<'a, str>),
}

/// A message being validated.
pub trait Message<R: Runtime> {
    /// Whether the field is set. Asked only of a field that
    /// [tracks presence](Field::has_presence); whether any other field is
    /// set follows from its value, which the validator decides for itself.
    ///
    /// # Errors
    ///
    /// The runtime could not tell.
    fn has(&self, field: &Field) -> Result<bool, ReadError>;

    /// The field's value, or its type's default when it is not set. `None`
    /// when the message has no such field, as when its runtime knows an
    /// older schema than the validator.
    ///
    /// # Errors
    ///
    /// The runtime could not read the field.
    fn get(&self, field: &Field) -> Result<Option<Val<'_, R>>, ReadError>;

    /// The message serialized, for the CEL runtime to parse when a rule binds
    /// it, or one of its repeated or map fields, to `this`.
    ///
    /// # Errors
    ///
    /// The runtime could not serialize the message.
    fn encode(&self) -> Result<Vec<u8>, ReadError>;
}

/// A repeated field.
// A length that may fail to be read has no `is_empty` to pair with.
#[allow(clippy::len_without_is_empty)]
pub trait List<R: Runtime> {
    /// The number of elements.
    ///
    /// # Errors
    ///
    /// The runtime could not count them.
    fn len(&self) -> Result<usize, ReadError>;

    /// The element at `index`, `None` past the end.
    ///
    /// # Errors
    ///
    /// The runtime could not read the element.
    fn get(&self, index: usize) -> Result<Option<Val<'_, R>>, ReadError>;
}

/// A map field. Iteration order is the runtime's.
// As for `List`.
#[allow(clippy::len_without_is_empty)]
pub trait Map<R: Runtime> {
    /// The number of entries.
    ///
    /// # Errors
    ///
    /// The runtime could not count them.
    fn len(&self) -> Result<usize, ReadError>;

    /// Visits each entry until `f` breaks.
    ///
    /// # Errors
    ///
    /// The runtime could not read an entry, where the visit stops.
    fn for_each(
        &self,
        f: &mut dyn FnMut(Key<'_>, Val<'_, R>) -> ControlFlow<()>,
    ) -> Result<(), ReadError>;
}
