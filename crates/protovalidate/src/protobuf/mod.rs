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
//! or map to `this` is the root message encoded, once, for the CEL runtime
//! to parse; that is what [`Payload::Encode`] defers.
//!
//! A runtime plugs in by implementing these and calling
//! [`Validator::validate_message`](crate::Validator::validate_message).
//! Each field the validator asks for comes described as a [`Field`],
//! resolved from the descriptors registered with it, so a runtime needs no
//! descriptors of its own: how a field is stored is all that is left to it.

use std::borrow::Cow;
use std::ops::ControlFlow;

mod field;

pub use field::{Field, Kind, Scalar, Singular};

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
    /// Whether the field is set: present for a field that
    /// [tracks presence](Field::has_presence), non-default otherwise,
    /// non-empty for a list or map.
    fn has(&self, field: &Field) -> bool;

    /// The field's value, or its type's default when it is not set. `None`
    /// when the message has no such field, as when its runtime knows an
    /// older schema than the validator.
    fn get(&self, field: &Field) -> Option<Val<'_, R>>;
}

/// A repeated field.
pub trait List<R: Runtime> {
    /// The number of elements.
    fn len(&self) -> usize;
    /// Whether there are no elements.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The element at `index`, `None` past the end.
    fn get(&self, index: usize) -> Option<Val<'_, R>>;
}

/// A map field. Iteration order is the runtime's.
pub trait Map<R: Runtime> {
    /// The number of entries.
    fn len(&self) -> usize;
    /// Whether there are no entries.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Visits each entry until `f` breaks.
    fn for_each(&self, f: &mut dyn FnMut(Key<'_>, Val<'_, R>) -> ControlFlow<()>);
}

/// The serialized root message, for the CEL runtime to parse when a rule
/// needs it.
#[derive(Clone, Copy)]
pub enum Payload<'a> {
    /// Already serialized.
    Bytes(&'a [u8]),
    /// Serialized on demand from the runtime's message.
    Encode(&'a dyn Fn() -> Vec<u8>),
}

#[cfg(feature = "cel")]
impl<'a> Payload<'a> {
    pub(crate) fn bytes(self) -> Cow<'a, [u8]> {
        match self {
            Self::Bytes(bytes) => Cow::Borrowed(bytes),
            Self::Encode(encode) => Cow::Owned(encode()),
        }
    }
}
