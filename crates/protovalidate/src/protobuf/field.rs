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

//! What the validator tells a runtime about a field it asks for.

use buffa::editions::FieldPresence;
use buffa_descriptor::{
    DescriptorPool, FieldDescriptor, FieldKind, MessageDescriptor, ScalarType, SingularKind,
};

use crate::descriptors;

/// A field of the message being validated, as the validator describes it
/// when asking a [`Message`](super::Message) for it.
///
/// The description is resolved from the descriptors registered with the
/// validator, and provided to a runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    number: u32,
    name: String,
    kind: Kind,
    message_type: Option<String>,
    has_presence: bool,
    oneof: Option<String>,
}

impl Field {
    pub(crate) fn from_descriptor(
        pool: &DescriptorPool,
        message: &MessageDescriptor,
        field: &FieldDescriptor,
    ) -> Self {
        let kind = match field.kind() {
            FieldKind::Singular(value) => Kind::Singular(singular(value)),
            FieldKind::List(element) => Kind::List(singular(element)),
            FieldKind::Map { key, value } => Kind::Map {
                key: scalar(key),
                value: singular(value),
            },
        };
        let oneof = field
            .oneof_index()
            .and_then(|index| message.oneofs().get(usize::from(index)))
            .filter(|oneof| !oneof.is_synthetic())
            .map(|oneof| oneof.name().to_owned());
        Self {
            number: field.number(),
            name: field.name().to_owned(),
            kind,
            message_type: descriptors::message_type(field)
                .map(|index| pool.message(index).full_name().to_owned()),
            has_presence: matches!(kind, Kind::Singular(_))
                && field.presence() != FieldPresence::Implicit,
            oneof,
        }
    }

    /// A field of a well-known type, which the rules read for themselves.
    /// The well-known types are proto3, so no such field tracks presence.
    pub(crate) fn well_known(number: u32, name: &str, kind: Kind) -> Self {
        Self {
            number,
            name: name.to_owned(),
            kind,
            message_type: None,
            has_presence: false,
            oneof: None,
        }
    }

    /// The field number.
    #[must_use]
    pub fn number(&self) -> u32 {
        self.number
    }

    /// The field's name in the `.proto` source.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// How the field holds its values.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The fully-qualified name of the message type the field holds: its
    /// value's for a singular field, its elements' for a list, its values'
    /// for a map. `None` when it is not a message.
    #[must_use]
    pub fn message_type(&self) -> Option<&str> {
        self.message_type.as_deref()
    }

    /// Whether the field tracks presence, so that
    /// [`Message::has`](super::Message::has) means set rather than
    /// non-default. Never for a list or map.
    #[must_use]
    pub fn has_presence(&self) -> bool {
        self.has_presence
    }

    /// The name of the oneof the field is a member of. A proto3 `optional`
    /// field's synthetic oneof does not count.
    #[must_use]
    pub fn oneof(&self) -> Option<&str> {
        self.oneof.as_deref()
    }
}

/// How a field holds its values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// One value.
    Singular(Singular),
    /// A repeated field.
    List(Singular),
    /// A map field.
    Map { key: Scalar, value: Singular },
}

/// The type of one value: a singular field's, a list's elements', a map's
/// keys' or values'.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Singular {
    Scalar(Scalar),
    /// An enum, read as its number.
    Enum,
    /// A message, of the type [`Field::message_type`] names.
    Message,
}

/// A Protobuf scalar type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    Bool,
    Int32,
    Int64,
    Uint32,
    Uint64,
    Sint32,
    Sint64,
    Fixed32,
    Fixed64,
    Sfixed32,
    Sfixed64,
    Float,
    Double,
    String,
    Bytes,
}

fn singular(kind: SingularKind) -> Singular {
    match kind {
        SingularKind::Scalar(scalar_type) => Singular::Scalar(scalar(scalar_type)),
        SingularKind::Enum(_) => Singular::Enum,
        SingularKind::Message(_) => Singular::Message,
    }
}

fn scalar(scalar: ScalarType) -> Scalar {
    match scalar {
        ScalarType::Bool => Scalar::Bool,
        ScalarType::Int32 => Scalar::Int32,
        ScalarType::Int64 => Scalar::Int64,
        ScalarType::Uint32 => Scalar::Uint32,
        ScalarType::Uint64 => Scalar::Uint64,
        ScalarType::Sint32 => Scalar::Sint32,
        ScalarType::Sint64 => Scalar::Sint64,
        ScalarType::Fixed32 => Scalar::Fixed32,
        ScalarType::Fixed64 => Scalar::Fixed64,
        ScalarType::Sfixed32 => Scalar::Sfixed32,
        ScalarType::Sfixed64 => Scalar::Sfixed64,
        ScalarType::Float => Scalar::Float,
        ScalarType::Double => Scalar::Double,
        ScalarType::String => Scalar::String,
        ScalarType::Bytes => Scalar::Bytes,
    }
}
