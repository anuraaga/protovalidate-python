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

//! Compiled validation rules, and their evaluation against messages.
//!
//! [`build`] turns the `buf.validate` options of a message type into a
//! [`MessageEvaluator`]: the standard rules as native [`standard::Check`]s,
//! the custom CEL rules as programs, and the structural checks
//! (`required`, `enum.defined_only`, `any.in`, oneofs), each already knowing
//! the path elements it reports. [`eval`] walks a message with them.

pub(crate) mod build;
pub(crate) mod eval;
pub(crate) mod standard;

use buffa_descriptor::{EnumIndex, MessageIndex, ScalarType};

#[cfg(feature = "cel")]
use crate::cel;
use crate::protobuf::Field;
use crate::validate::FieldPathElement;
use standard::Check;

#[cfg(feature = "cel")]
/// What a CEL expression reports when it fails.
pub(crate) struct RuleMeta {
    pub id: String,
    pub message: String,
    pub expression: String,
    /// The rule path, leaf first: `[FieldRules.cel[i]]` for a custom rule,
    /// `[(pkg.rule), FieldRules.string]` for a predefined one, empty for a
    /// message-level one. Paths are built leaf-first as violations bubble
    /// up, and reversed once at the end.
    pub rule_path: Vec<FieldPathElement>,
}

#[cfg(feature = "cel")]
/// CEL expressions evaluated together against one `this`.
pub(crate) struct ProgramSet {
    pub program: cel::Program,
    pub rules: Vec<RuleMeta>,
}

/// The rules of one message type, in evaluation order: message-level CEL,
/// message oneofs, the fields in declaration order, then oneof declarations.
pub(crate) struct MessageEvaluator {
    #[cfg(feature = "cel")]
    pub cel: Option<ProgramSet>,
    pub message_oneofs: Vec<MessageOneof>,
    pub fields: Vec<FieldEvaluator>,
    pub oneofs: Vec<OneofRequired>,
    /// Message-typed fields to descend into, in field-number order.
    pub nested: Vec<Nested>,
}

/// A `(buf.validate.message).oneof` rule.
pub(crate) struct MessageOneof {
    pub fields: Vec<Field>,
    /// The member names joined with `, `, as the violation message prints them.
    pub names: String,
    pub required: bool,
}

/// A `(buf.validate.oneof).required` rule.
pub(crate) struct OneofRequired {
    pub element: FieldPathElement,
    pub members: Vec<Field>,
}

/// A message-typed field whose messages are validated in turn.
pub(crate) struct Nested {
    pub field: Field,
    /// The path element; for a map, the entry form carrying key and value
    /// types, to which the key subscript is added.
    pub element: FieldPathElement,
    pub shape: Shape,
    pub message: MessageIndex,
}

/// How a field holds its values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    Singular,
    List,
    Map { key: ScalarType },
}

/// The rules of one value: a field's, or one element, key or value of a
/// container field's. The checks run first, then the custom CEL.
pub(crate) struct ValueRules {
    /// The value is a scalar (as opposed to a message) so `this` is bound
    /// directly rather than through the frame.
    #[cfg(feature = "cel")]
    pub scalar: Option<ScalarKind>,
    pub ignore_empty: bool,
    pub any: Option<AnyCheck>,
    /// The standard rules, in evaluation order.
    pub checks: Vec<Check>,
    /// The value is a wrapper message, and the checks apply to this field
    /// of it: its `value`.
    pub wrapper: Option<Field>,
    /// The custom CEL rules, which run after the standard ones.
    #[cfg(feature = "cel")]
    pub programs: Option<ProgramSet>,
}

/// The rules of one field.
pub(crate) struct FieldEvaluator {
    pub field: Field,
    pub element: FieldPathElement,
    /// For maps, the element form carrying key and value types, to which
    /// the key subscript is added for per-entry violations.
    pub entry_element: Option<FieldPathElement>,
    pub shape: Shape,
    pub required: bool,
    pub rules: ValueRules,
    /// `enum.defined_only`, checked against this enum's values.
    pub defined_only: Option<EnumIndex>,
    pub items: Option<ItemEvaluator>,
    pub keys: Option<ItemEvaluator>,
    pub values: Option<ItemEvaluator>,
}

/// The rules of the elements of a repeated field, or the keys or values of
/// a map.
pub(crate) struct ItemEvaluator {
    pub rules: ValueRules,
    /// The rule path elements between the item rules and `FieldRules`, leaf
    /// first: `[RepeatedRules.items, FieldRules.repeated]`.
    pub rule_prefix: [FieldPathElement; 2],
}

/// `any.in` and `any.not_in`.
pub(crate) struct AnyCheck {
    pub r#in: Vec<String>,
    pub not_in: Vec<String>,
}

/// How a scalar field's values are handed to CEL.
#[cfg(feature = "cel")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScalarKind {
    Bool,
    Int,
    Uint,
    Double,
    String,
    Bytes,
}
