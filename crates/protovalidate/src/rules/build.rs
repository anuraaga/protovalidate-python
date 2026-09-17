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

//! Building evaluators from a message type's `buf.validate` options.
//!
//! Standard rules are checked with directly. Only custom CEL reaches the CEL
//! backend: message- and field-level `cel` options, and user-defined
//! predefined rules on extension fields, whose expressions are compiled with
//! `rules` bound to the rules message and `rule` to that field. The
//! structural rules -- `required`, `ignore`, `enum.defined_only`,
//! `any.in`/`not_in`, and the oneof rules -- are checked by the walker
//! directly.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use buffa::editions::FieldPresence;
use buffa_descriptor::generated::descriptor::field_descriptor_proto::Type;
use buffa_descriptor::reflect::{DynamicMessage, ReflectMessage as _};
use buffa_descriptor::{
    DescriptorPool, EnumIndex, FieldDescriptor, FieldKind, MessageDescriptor, MessageIndex,
    SingularKind,
};

use super::standard::{self, Check};
use super::{
    AnyCheck, FieldEvaluator, ItemEvaluator, MessageEvaluator, MessageOneof, Nested, OneofRequired,
    Shape, ValueRules,
};
#[cfg(feature = "cel")]
use super::{ProgramSet, RuleMeta, ScalarKind};
use crate::Error;
#[cfg(feature = "cel")]
use crate::cel::{Env, Expression};
use crate::descriptors::{self, Descriptors};
use crate::protobuf::Field;
use crate::validate::__buffa::oneof::field_path_element::Subscript;
use crate::validate::__buffa::oneof::field_rules::Type as RulesType;
use crate::validate::{FieldPathElement, FieldRules, Ignore, MessageRules, Rule};

/// Compiles the rules of message types.
pub(crate) struct Builder<'a> {
    descriptors: &'a Descriptors,
    #[cfg(feature = "cel")]
    env: &'a mut Env,
}

/// A standard rules message (`StringRules`, `RepeatedRules`, ...), by full
/// name and serialized form.
trait RulesMessage {
    fn full_name(&self) -> &'static str;
    fn to_bytes(&self) -> Vec<u8>;
}

impl<M: buffa::Message + buffa::MessageName> RulesMessage for M {
    fn full_name(&self) -> &'static str {
        M::FULL_NAME
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

/// The value a set of rules applies to: a field, or the elements, keys or
/// values of one.
#[derive(Clone, Copy)]
struct Target {
    /// What one value is.
    kind: SingularKind,
    /// Its `FieldDescriptorProto.Type`, for type checks and path elements.
    ty: Type,
    /// The container it comes from; a repeated field's elements still count
    /// as a repeated field.
    shape: Shape,
    /// The presence of the field itself, for singular fields.
    presence: FieldPresence,
    /// Whether this is a map entry's key or value, which never ignores
    /// unset values on its own.
    map_entry: bool,
}

/// The rules of one value, before they are placed as a field or item
/// evaluator: the value's own, and the ones only a field carries.
struct Built {
    rules: ValueRules,
    required: bool,
    defined_only: Option<EnumIndex>,
    items: Option<ItemEvaluator>,
    keys: Option<ItemEvaluator>,
    values: Option<ItemEvaluator>,
}

/// The custom CEL of one field or message: the expressions to compile, what
/// each reports, and the rules message the predefined ones bind as `rules`.
struct Compiled {
    expressions: Vec<(String, i32)>,
    #[cfg(feature = "cel")]
    metas: Vec<RuleMeta>,
    #[cfg(feature = "cel")]
    rules: Option<(&'static str, Vec<u8>)>,
}

impl Compiled {
    fn new() -> Self {
        Self {
            expressions: Vec::new(),
            #[cfg(feature = "cel")]
            metas: Vec::new(),
            #[cfg(feature = "cel")]
            rules: None,
        }
    }

    // `rule_path` is reported by CEL violations.
    #[cfg_attr(not(feature = "cel"), expect(unused_variables))]
    fn push(&mut self, rule: &Rule, rule_field_number: i32, rule_path: &[FieldPathElement]) {
        let expression = rule.expression.clone().unwrap_or_default();
        #[cfg(feature = "cel")]
        self.metas.push(RuleMeta {
            id: rule.id.clone().unwrap_or_default(),
            message: rule.message.clone().unwrap_or_default(),
            expression: expression.clone(),
            rule_path: rule_path.to_vec(),
        });
        self.expressions.push((expression, rule_field_number));
    }

    /// Custom CEL rules need the `cel` feature; fails if there are any.
    #[cfg(not(feature = "cel"))]
    fn reject(self) -> Result<(), Error> {
        if self.expressions.is_empty() {
            Ok(())
        } else {
            Err(Error::Compilation(
                "custom CEL rules require the `cel` feature of the protovalidate crate".to_owned(),
            ))
        }
    }
}

fn rule_from_expression(expression: &str) -> Rule {
    Rule {
        id: Some(expression.to_owned()),
        message: Some(String::new()),
        expression: Some(expression.to_owned()),
        ..Default::default()
    }
}

fn indexed(mut element: FieldPathElement, index: usize) -> FieldPathElement {
    element.subscript = Some(Subscript::Index(index as u64));
    element
}

#[cfg(feature = "cel")]
fn scalar_kind(kind: SingularKind) -> Option<ScalarKind> {
    use buffa_descriptor::ScalarType as S;
    match kind {
        SingularKind::Scalar(scalar) => Some(match scalar {
            S::Bool => ScalarKind::Bool,
            S::Int32 | S::Int64 | S::Sint32 | S::Sint64 | S::Sfixed32 | S::Sfixed64 => {
                ScalarKind::Int
            }
            S::Uint32 | S::Uint64 | S::Fixed32 | S::Fixed64 => ScalarKind::Uint,
            S::Float | S::Double => ScalarKind::Double,
            S::String => ScalarKind::String,
            S::Bytes => ScalarKind::Bytes,
        }),
        SingularKind::Enum(_) => Some(ScalarKind::Int),
        SingularKind::Message(_) => None,
    }
}

fn singular_type(kind: SingularKind) -> Type {
    match kind {
        SingularKind::Scalar(scalar) => descriptors::scalar_type(scalar),
        SingularKind::Enum(_) => Type::TYPE_ENUM,
        SingularKind::Message(_) => Type::TYPE_MESSAGE,
    }
}

fn shape_of(field: &FieldDescriptor) -> Shape {
    match field.kind() {
        FieldKind::Singular(_) => Shape::Singular,
        FieldKind::List(_) => Shape::List,
        FieldKind::Map { key, .. } => Shape::Map { key },
    }
}

/// The path element for a map field's entries, which carries the key and
/// value types alongside the field.
fn entry_element(field: &FieldDescriptor) -> FieldPathElement {
    let mut element = descriptors::path_element(field);
    if let FieldKind::Map { key, value } = field.kind() {
        element.key_type = Some(descriptors::scalar_type(key));
        element.value_type = Some(singular_type(value));
    }
    element
}

fn ignore_always(rules: &FieldRules) -> bool {
    rules.ignore == Some(Ignore::IGNORE_ALWAYS)
}

/// The standard rules of a scalar type: the rules message, the `FieldRules`
/// field holding it, the field type it expects, and the wrapper message that
/// also satisfies it (none for the types without a wrapper).
fn scalar_rules(
    rules: &RulesType,
) -> Option<(&dyn RulesMessage, &'static str, Type, &'static str)> {
    Some(match rules {
        RulesType::Float(r) => (
            r.as_ref(),
            "float",
            Type::TYPE_FLOAT,
            "google.protobuf.FloatValue",
        ),
        RulesType::Double(r) => (
            r.as_ref(),
            "double",
            Type::TYPE_DOUBLE,
            "google.protobuf.DoubleValue",
        ),
        RulesType::Int32(r) => (
            r.as_ref(),
            "int32",
            Type::TYPE_INT32,
            "google.protobuf.Int32Value",
        ),
        RulesType::Int64(r) => (
            r.as_ref(),
            "int64",
            Type::TYPE_INT64,
            "google.protobuf.Int64Value",
        ),
        RulesType::Uint32(r) => (
            r.as_ref(),
            "uint32",
            Type::TYPE_UINT32,
            "google.protobuf.UInt32Value",
        ),
        RulesType::Uint64(r) => (
            r.as_ref(),
            "uint64",
            Type::TYPE_UINT64,
            "google.protobuf.UInt64Value",
        ),
        RulesType::Sint32(r) => (r.as_ref(), "sint32", Type::TYPE_SINT32, ""),
        RulesType::Sint64(r) => (r.as_ref(), "sint64", Type::TYPE_SINT64, ""),
        RulesType::Fixed32(r) => (r.as_ref(), "fixed32", Type::TYPE_FIXED32, ""),
        RulesType::Fixed64(r) => (r.as_ref(), "fixed64", Type::TYPE_FIXED64, ""),
        RulesType::Sfixed32(r) => (r.as_ref(), "sfixed32", Type::TYPE_SFIXED32, ""),
        RulesType::Sfixed64(r) => (r.as_ref(), "sfixed64", Type::TYPE_SFIXED64, ""),
        RulesType::Bool(r) => (
            r.as_ref(),
            "bool",
            Type::TYPE_BOOL,
            "google.protobuf.BoolValue",
        ),
        RulesType::String(r) => (
            r.as_ref(),
            "string",
            Type::TYPE_STRING,
            "google.protobuf.StringValue",
        ),
        RulesType::Bytes(r) => (
            r.as_ref(),
            "bytes",
            Type::TYPE_BYTES,
            "google.protobuf.BytesValue",
        ),
        RulesType::Enum(r) => (r.as_ref(), "enum", Type::TYPE_ENUM, ""),
        RulesType::Repeated(_)
        | RulesType::Map(_)
        | RulesType::Any(_)
        | RulesType::Duration(_)
        | RulesType::FieldMask(_)
        | RulesType::Timestamp(_) => return None,
    })
}

impl<'a> Builder<'a> {
    #[cfg(feature = "cel")]
    pub(crate) fn new(descriptors: &'a Descriptors, env: &'a mut Env) -> Self {
        Self { descriptors, env }
    }

    #[cfg(not(feature = "cel"))]
    pub(crate) fn new(descriptors: &'a Descriptors) -> Self {
        Self { descriptors }
    }

    /// Compiles `root` and every message type reachable from it that
    /// `known` does not already hold, into `out`.
    ///
    /// The whole closure is compiled up front, so a rule that does not
    /// compile anywhere below the root is reported before any message is
    /// validated.
    pub(crate) fn build_closure(
        &mut self,
        root: MessageIndex,
        known: &HashMap<MessageIndex, Arc<MessageEvaluator>>,
        out: &mut HashMap<MessageIndex, Arc<MessageEvaluator>>,
    ) -> Result<(), Error> {
        // The reference is copied out of `self`, so the loop below can still
        // take `&mut self`.
        let descriptors: &'a Descriptors = self.descriptors;
        let pool = &descriptors.pool;
        let mut pending = vec![root];
        while let Some(idx) = pending.pop() {
            if known.contains_key(&idx) || out.contains_key(&idx) {
                continue;
            }
            let evaluator = self.build_message(pool.message(idx))?;
            out.insert(idx, Arc::new(evaluator));
            for field in pool.message(idx).fields() {
                if let Some(nested) = descriptors::message_type(field) {
                    pending.push(nested);
                }
            }
        }
        Ok(())
    }

    /// The rules of a message type.
    fn build_message(&mut self, message: &MessageDescriptor) -> Result<MessageEvaluator, Error> {
        let pool = &*self.descriptors.pool;
        let rules = descriptors::message_rules(message);
        let compiled = rules
            .as_ref()
            .map_or_else(Compiled::new, message_expressions);
        #[cfg(feature = "cel")]
        let cel = self.compile(compiled)?;
        #[cfg(not(feature = "cel"))]
        compiled.reject()?;
        let MessageLevel {
            oneofs: message_oneofs,
            members: oneof_members,
        } = match &rules {
            Some(rules) => message_oneofs(pool, message, rules)?,
            None => MessageLevel::default(),
        };

        let mut fields = Vec::new();
        for field in message.fields() {
            let Some(mut field_rules) = descriptors::field_rules(field) else {
                continue;
            };
            // A member of a message oneof is only validated when set, unless
            // it says otherwise.
            if field_rules.ignore.is_none() && oneof_members.contains(field.name()) {
                field_rules.ignore = Some(Ignore::IGNORE_IF_ZERO_VALUE);
            }
            if let Some(evaluator) = self.build_field(field, &field_rules)? {
                fields.push(evaluator);
            }
        }

        Ok(MessageEvaluator {
            #[cfg(feature = "cel")]
            cel,
            message_oneofs,
            fields,
            oneofs: Self::required_oneofs(pool, message),
            nested: Self::nested_fields(pool, message),
        })
    }

    /// The oneof declarations marked `required`.
    fn required_oneofs(pool: &DescriptorPool, message: &MessageDescriptor) -> Vec<OneofRequired> {
        message
            .oneofs()
            .iter()
            .filter(|oneof| {
                descriptors::oneof_rules(oneof).is_some_and(|rules| rules.required.unwrap_or(false))
            })
            .map(|oneof| OneofRequired {
                element: descriptors::oneof_path_element(oneof.name()),
                members: oneof
                    .field_indices()
                    .iter()
                    .filter_map(|&index| message.fields().get(usize::from(index)))
                    .map(|field| Field::from_descriptor(pool, field))
                    .collect(),
            })
            .collect()
    }

    /// The message-typed fields whose messages are validated in turn, in
    /// field-number order, less the ones told to ignore their messages.
    fn nested_fields(pool: &DescriptorPool, message: &MessageDescriptor) -> Vec<Nested> {
        let mut nested = Vec::new();
        for field in message.fields() {
            let Some(nested_message) = descriptors::message_type(field) else {
                continue;
            };
            if let Some(rules) = descriptors::field_rules(field) {
                let items_ignored = match &rules.r#type {
                    Some(RulesType::Repeated(repeated)) => {
                        repeated.items.as_option().is_some_and(ignore_always)
                    }
                    Some(RulesType::Map(map)) => map.values.as_option().is_some_and(ignore_always),
                    _ => false,
                };
                if ignore_always(&rules) || items_ignored {
                    continue;
                }
            }
            let shape = shape_of(field);
            nested.push(Nested {
                field: Field::from_descriptor(pool, field),
                element: match shape {
                    Shape::Map { .. } => entry_element(field),
                    Shape::Singular | Shape::List => descriptors::path_element(field),
                },
                shape,
                message: nested_message,
            });
        }
        nested.sort_by_key(|nested| nested.field.number());
        nested
    }

    fn build_field(
        &mut self,
        field: &FieldDescriptor,
        rules: &FieldRules,
    ) -> Result<Option<FieldEvaluator>, Error> {
        let shape = shape_of(field);
        let kind = match field.kind() {
            FieldKind::Singular(kind) | FieldKind::List(kind) => kind,
            FieldKind::Map { value, .. } => value,
        };
        let target = Target {
            kind,
            ty: descriptors::proto_type(field),
            shape,
            presence: field.presence(),
            map_entry: false,
        };
        let Some(built) = self.build_value(target, rules)? else {
            return Ok(None);
        };
        Ok(Some(FieldEvaluator {
            field: Field::from_descriptor(&self.descriptors.pool, field),
            element: descriptors::path_element(field),
            entry_element: match shape {
                Shape::Map { .. } => Some(entry_element(field)),
                Shape::Singular | Shape::List => None,
            },
            shape,
            required: built.required,
            rules: built.rules,
            defined_only: built.defined_only,
            items: built.items,
            keys: built.keys,
            values: built.values,
        }))
    }

    /// The rules of one value.
    fn build_value(&mut self, target: Target, rules: &FieldRules) -> Result<Option<Built>, Error> {
        if ignore_always(rules) {
            return Ok(None);
        }
        let ignore_empty = rules.ignore == Some(Ignore::IGNORE_IF_ZERO_VALUE)
            || (target.shape == Shape::Singular
                && target.presence != FieldPresence::Implicit
                && !target.map_entry);
        let mut built = Built {
            rules: ValueRules {
                #[cfg(feature = "cel")]
                scalar: scalar_kind(target.kind),
                ignore_empty,
                any: None,
                checks: Vec::new(),
                wrapper: None,
                #[cfg(feature = "cel")]
                programs: None,
            },
            required: rules.required.unwrap_or(false),
            defined_only: None,
            items: None,
            keys: None,
            values: None,
        };

        let mut compiled = Compiled::new();
        if let Some(standard) = &rules.r#type {
            self.standard_rules(target, standard, &mut built, &mut compiled)?;
        }

        let schema = &self.descriptors.schema;
        for (index, expression) in rules.cel_expression.iter().enumerate() {
            compiled.push(
                &rule_from_expression(expression),
                0,
                &[indexed(schema.cel_expression.clone(), index)],
            );
        }
        for (index, rule) in rules.cel.iter().enumerate() {
            compiled.push(rule, 0, &[indexed(schema.cel.clone(), index)]);
        }
        #[cfg(feature = "cel")]
        {
            built.rules.programs = self.compile(compiled)?;
        }
        #[cfg(not(feature = "cel"))]
        compiled.reject()?;
        Ok(Some(built))
    }

    /// The standard rules a `FieldRules` sets, checked against the value's
    /// type.
    fn standard_rules(
        &mut self,
        target: Target,
        standard: &RulesType,
        built: &mut Built,
        compiled: &mut Compiled,
    ) -> Result<(), Error> {
        let pool = &self.descriptors.pool;
        let message_name = |kind: SingularKind| match kind {
            SingularKind::Message(idx) => Some(pool.message(idx).full_name()),
            _ => None,
        };
        if let Some((rules, name, expected, wrapper)) = scalar_rules(standard) {
            self.check_scalar_type(&target, expected, wrapper)?;
            built.rules.wrapper = self.wrapper_value(&target);
            if let RulesType::Enum(r) = standard {
                if r.defined_only.unwrap_or(false) && target.shape == Shape::Singular {
                    if let SingularKind::Enum(idx) = target.kind {
                        built.defined_only = Some(idx);
                    }
                }
            }
            return self.predefined_rules(name, standard, rules, &mut built.rules.checks, compiled);
        }
        let (name, rules): (&'static str, &dyn RulesMessage) = match standard {
            RulesType::Duration(r) => {
                if message_name(target.kind) != Some(descriptors::DURATION) {
                    return Err(Error::Compilation(
                        "duration field validator on non-duration field".to_owned(),
                    ));
                }
                ("duration", r.as_ref())
            }
            RulesType::FieldMask(r) => {
                if message_name(target.kind) != Some(descriptors::FIELD_MASK) {
                    return Err(Error::Compilation(
                        "field_mask field validator on non-field_mask field".to_owned(),
                    ));
                }
                ("field_mask", r.as_ref())
            }
            RulesType::Timestamp(r) => {
                if message_name(target.kind) != Some(descriptors::TIMESTAMP) {
                    return Err(Error::Compilation(
                        "timestamp field validator on non-timestamp field".to_owned(),
                    ));
                }
                ("timestamp", r.as_ref())
            }
            RulesType::Repeated(r) => {
                built.items = self.item_rules(target, r.items.as_option())?;
                ("repeated", r.as_ref())
            }
            RulesType::Map(r) => {
                let (keys, values) =
                    self.entry_rules(target, r.keys.as_option(), r.values.as_option())?;
                built.keys = keys;
                built.values = values;
                ("map", r.as_ref())
            }
            RulesType::Any(r) => {
                if message_name(target.kind) != Some(descriptors::ANY) {
                    return Err(Error::Compilation(
                        "any field validator on non-any field".to_owned(),
                    ));
                }
                built.rules.any = Some(AnyCheck {
                    r#in: r.r#in.clone(),
                    not_in: r.not_in.clone(),
                });
                ("any", r.as_ref())
            }
            _ => return Ok(()),
        };
        self.predefined_rules(name, standard, rules, &mut built.rules.checks, compiled)
    }

    /// The rules of a repeated field's elements. Each element is validated
    /// as a value of the element type that still belongs to a repeated
    /// field.
    fn item_rules(
        &mut self,
        target: Target,
        items: Option<&FieldRules>,
    ) -> Result<Option<ItemEvaluator>, Error> {
        match target.shape {
            Shape::List => {}
            Shape::Map { .. } => {
                return Err(Error::Compilation(
                    "repeated field validator on map field".to_owned(),
                ));
            }
            Shape::Singular => {
                return Err(Error::Compilation(
                    "repeated field validator on non-repeated field".to_owned(),
                ));
            }
        }
        let Some(items) = items else {
            return Ok(None);
        };
        let item_target = Target {
            ty: singular_type(target.kind),
            ..target
        };
        Ok(self
            .build_value(item_target, items)?
            .map(|built| self.item_evaluator(built, ItemKind::Items)))
    }

    /// The rules of a map field's keys and values.
    fn entry_rules(
        &mut self,
        target: Target,
        keys: Option<&FieldRules>,
        values: Option<&FieldRules>,
    ) -> Result<(Option<ItemEvaluator>, Option<ItemEvaluator>), Error> {
        let Shape::Map { key } = target.shape else {
            return Err(Error::Compilation(
                "map field validator on non-map field".to_owned(),
            ));
        };
        let entry = |kind: SingularKind| Target {
            kind,
            ty: singular_type(kind),
            shape: Shape::Singular,
            presence: FieldPresence::Explicit,
            map_entry: true,
        };
        let keys = match keys {
            Some(keys) => self
                .build_value(entry(SingularKind::Scalar(key)), keys)?
                .map(|built| self.item_evaluator(built, ItemKind::Keys)),
            None => None,
        };
        let values = match values {
            Some(values) => self
                .build_value(entry(target.kind), values)?
                .map(|built| self.item_evaluator(built, ItemKind::Values)),
            None => None,
        };
        Ok((keys, values))
    }

    fn item_evaluator(&self, built: Built, kind: ItemKind) -> ItemEvaluator {
        let schema = &self.descriptors.schema;
        let rule_prefix = match kind {
            ItemKind::Items => [schema.repeated_items.clone(), schema.repeated.clone()],
            ItemKind::Keys => [schema.map_keys.clone(), schema.map.clone()],
            ItemKind::Values => [schema.map_values.clone(), schema.map.clone()],
        };
        ItemEvaluator {
            rules: built.rules,
            rule_prefix,
        }
    }

    /// The `value` field of the wrapper message a target holds, if it is one;
    /// `check_scalar_type` has already established that it is a wrapper.
    fn wrapper_value(&self, target: &Target) -> Option<Field> {
        if target.ty != Type::TYPE_MESSAGE {
            return None;
        }
        let SingularKind::Message(idx) = target.kind else {
            return None;
        };
        let pool = &*self.descriptors.pool;
        let wrapper = pool.message(idx);
        let value = wrapper.field(1)?;
        Some(Field::from_descriptor(pool, value))
    }

    /// The field must have the rules' type, or be the wrapper message of that
    /// type.
    fn check_scalar_type(
        &self,
        target: &Target,
        expected: Type,
        wrapper: &str,
    ) -> Result<(), Error> {
        if target.ty == expected {
            return Ok(());
        }
        if target.ty == Type::TYPE_MESSAGE {
            if let SingularKind::Message(idx) = target.kind {
                if self.descriptors.pool.message(idx).full_name() == wrapper {
                    return Ok(());
                }
            }
        }
        Err(Error::Compilation(format!(
            "field type does not match rule type: {} != {}",
            descriptors::type_name(target.ty),
            descriptors::type_name(expected)
        )))
    }

    /// The rules of every rule field the rules message sets, in field-number
    /// order.
    fn predefined_rules(
        &self,
        type_field: &'static str,
        standard: &RulesType,
        rules: &dyn RulesMessage,
        checks: &mut Vec<Check>,
        compiled: &mut Compiled,
    ) -> Result<(), Error> {
        let pool = &self.descriptors.pool;
        let full_name = rules.full_name();
        let bytes = rules.to_bytes();
        let idx = pool
            .message_index(full_name)
            .unwrap_or_else(|| panic!("{full_name} is in the embedded descriptor set"));
        let dynamic = DynamicMessage::decode(Arc::clone(pool), idx, &bytes).map_err(|error| {
            Error::Compilation(format!("could not decode {full_name}: {error}"))
        })?;
        if !dynamic.unknown_fields().is_empty() {
            return Err(Error::Compilation(format!("unknown rules in {full_name}")));
        }
        let type_element = self.descriptors.schema.type_element(pool, type_field);
        let message = pool.message(idx);
        let mut failed = None;
        dynamic.for_each_set(&mut |field, _value| {
            if message.field(field.number()).is_some() {
                let element = descriptors::path_element(field);
                match standard::build::checks(type_field, standard, field.number()) {
                    Ok(natives) => checks.extend(natives.into_iter().map(|native| Check {
                        id: native.id,
                        message: native.message,
                        rule_path: [element.clone(), type_element.clone()],
                        test: native.test,
                    })),
                    Err(error) => {
                        failed.get_or_insert(error);
                    }
                }
                return;
            }
            let element = match pool.extension_for(idx, field.number()) {
                Some(extension) => descriptors::extension_path_element(extension),
                None => descriptors::path_element(field),
            };
            let Some(predefined) = descriptors::predefined_rules(field) else {
                return;
            };
            let number = i32::try_from(field.number()).unwrap_or(0);
            for rule in &predefined.cel {
                compiled.push(rule, number, &[element.clone(), type_element.clone()]);
            }
        });
        if let Some(error) = failed {
            return Err(error);
        }
        #[cfg(feature = "cel")]
        {
            compiled.rules = Some((full_name, bytes));
        }
        Ok(())
    }

    #[cfg(feature = "cel")]
    fn compile(&mut self, compiled: Compiled) -> Result<Option<ProgramSet>, Error> {
        if compiled.expressions.is_empty() {
            return Ok(None);
        }
        let rules = compiled
            .rules
            .as_ref()
            .map(|(name, bytes)| (*name, bytes.as_slice()));
        let expressions: Vec<Expression<'_>> = compiled
            .expressions
            .iter()
            .map(|(expression, rule_field_number)| Expression {
                expression,
                rule_field_number: *rule_field_number,
            })
            .collect();
        let program = self
            .env
            .compile(rules, &expressions)
            .map_err(|error| Error::Compilation(error.message().to_owned()))?;
        Ok(Some(ProgramSet {
            program,
            rules: compiled.metas,
        }))
    }
}

/// The `(buf.validate.message).cel_expression` and `.cel` rules, in that
/// order.
fn message_expressions(rules: &MessageRules) -> Compiled {
    let mut compiled = Compiled::new();
    for expression in &rules.cel_expression {
        compiled.push(&rule_from_expression(expression), 0, &[]);
    }
    for rule in &rules.cel {
        compiled.push(rule, 0, &[]);
    }
    compiled
}

/// The `(buf.validate.message).oneof` rules, and the fields they name.
fn message_oneofs<'m>(
    pool: &DescriptorPool,
    message: &'m MessageDescriptor,
    rules: &'m MessageRules,
) -> Result<MessageLevel<'m>, Error> {
    let mut oneofs = Vec::new();
    let mut members = HashSet::new();
    for oneof in &rules.oneof {
        if oneof.fields.is_empty() {
            return Err(Error::Compilation(format!(
                "at least one field must be specified in oneof rule for the message {}",
                message.full_name()
            )));
        }
        let mut seen = HashSet::new();
        let mut fields = Vec::with_capacity(oneof.fields.len());
        for name in &oneof.fields {
            if !seen.insert(name.as_str()) {
                return Err(Error::Compilation(format!(
                    "duplicate \"{name}\" in oneof rule for the message {}",
                    message.full_name()
                )));
            }
            let Some(field) = message.field_by_name(name) else {
                return Err(Error::Compilation(format!(
                    "field \"{name}\" not found in message {}",
                    message.full_name()
                )));
            };
            fields.push(Field::from_descriptor(pool, field));
        }
        oneofs.push(MessageOneof {
            fields,
            names: oneof.fields.join(", "),
            required: oneof.required.unwrap_or(false),
        });
        members.extend(oneof.fields.iter().map(String::as_str));
    }
    Ok(MessageLevel { oneofs, members })
}

/// A message's oneof rules, and the fields they name.
#[derive(Default)]
struct MessageLevel<'m> {
    oneofs: Vec<MessageOneof>,
    members: HashSet<&'m str>,
}

/// Which items of a container an [`ItemEvaluator`] is for.
#[derive(Clone, Copy)]
enum ItemKind {
    Items,
    Keys,
    Values,
}
