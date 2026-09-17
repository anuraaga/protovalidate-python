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

//! Walking a message with its evaluators.
//!
//! The walk runs the message's own rules, then its fields' rules, then the
//! same for every set message-typed field. Violations are collected with their paths built
//! leaf first -- each level appends the element that led to it -- and the
//! paths are reversed once at the end.
//!
//! The message is read through [`crate::protobuf`], so the walk is generic
//! over the runtime holding it. CEL sees messages through a [`LazyFrame`]:
//! the root is handed to the CEL runtime only if some custom rule needs a
//! message, list or map bound to `this`. A field of the root is reached
//! inside that one parse; a message the walk descends into is encoded on
//! its own, again only if a rule asks.

#[cfg(feature = "cel")]
use std::cell::OnceCell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::ControlFlow;
use std::sync::Arc;

use buffa_descriptor::{DescriptorPool, MessageIndex};

use super::standard::Check;
use super::{
    AnyCheck, FieldEvaluator, ItemEvaluator, MessageEvaluator, MessageOneof, OneofRequired, Shape,
    ValueRules,
};
#[cfg(feature = "cel")]
use super::{ProgramSet, ScalarKind};
use crate::Error;
#[cfg(feature = "cel")]
use crate::cel::{self, Env, Scalar, This, Value};
use crate::descriptors::{self, Descriptors, Schema};
use crate::protobuf::{Field, Key, List as _, Map as _, Message as _, ReadError, Runtime, Val};
use crate::validate::__buffa::oneof::field_path_element::Subscript;
use crate::validate::{FieldPath, FieldPathElement, Violation};

/// Serializes a message, when CEL asks for it.
type Encode<'a> = &'a dyn Fn() -> Result<Vec<u8>, ReadError>;

/// A message as CEL sees it, parsed on first use.
///
/// A frame knows how to serialize one message -- the root, or a sub-message
/// as its runtime encodes it -- and parses it the first time a program asks.
/// Frames nest on the stack the way the walk does, so one outlives every
/// program run against it.
#[cfg(feature = "cel")]
pub(crate) struct LazyFrame<'a> {
    env: &'a Env,
    type_name: &'a str,
    encode: Encode<'a>,
    parsed: OnceCell<cel::Frame>,
}

/// Where CEL would see a message; without the `cel` feature no rule ever
/// asks, so the frames carry nothing.
#[cfg(not(feature = "cel"))]
pub(crate) struct LazyFrame<'a>(PhantomData<&'a ()>);

#[cfg(not(feature = "cel"))]
impl<'a> LazyFrame<'a> {
    fn root(_type_name: &'a str, _encode: Encode<'a>) -> Self {
        Self(PhantomData)
    }

    fn child(_parent: &LazyFrame<'a>, _type_name: &'a str, _encode: Encode<'a>) -> Self {
        Self(PhantomData)
    }
}

#[cfg(feature = "cel")]
impl<'a> LazyFrame<'a> {
    fn new(env: &'a Env, type_name: &'a str, encode: Encode<'a>) -> Self {
        Self {
            env,
            type_name,
            encode,
            parsed: OnceCell::new(),
        }
    }

    fn root(env: &'a Env, type_name: &'a str, encode: Encode<'a>) -> Self {
        Self::new(env, type_name, encode)
    }

    /// A sub-message of `parent`'s, from its own encoding.
    fn child(parent: &LazyFrame<'a>, type_name: &'a str, encode: Encode<'a>) -> Self {
        Self::new(parent.env, type_name, encode)
    }

    /// The parsed message.
    fn parsed(&self) -> Result<&cel::Frame, Error> {
        if self.parsed.get().is_none() {
            let frame = self.env.frame(self.type_name, &(self.encode)()?)?;
            let _ = self.parsed.set(frame);
        }
        Ok(self.parsed.get().expect("frame was just set"))
    }
}

#[cfg(feature = "cel")]
fn field_number(number: u32) -> i32 {
    i32::try_from(number).unwrap_or(i32::MAX)
}

/// The type of the messages a field holds, which a frame of one of them is
/// parsed as.
fn message_type(field: &Field) -> Result<&str, Error> {
    field
        .message_type()
        .ok_or_else(|| Error::Unexpected(format!("{} does not hold messages", field.name())))
}

/// Whether a repeated element or map value is the zero of its type, as
/// `IGNORE_IF_ZERO_VALUE` reads it.
fn is_empty_item<R: Runtime>(value: &Val<'_, R>) -> bool {
    match value {
        Val::Bool(b) => !b,
        Val::Int(i) => *i == 0,
        Val::Uint(u) => *u == 0,
        Val::Double(f) => *f == 0.0,
        Val::Enum(e) => *e == 0,
        Val::String(s) => s.is_empty(),
        Val::Bytes(b) => b.is_empty(),
        Val::Message(_) | Val::List(_) | Val::Map(_) => false,
    }
}

/// Whether a field that does not track presence is set: not its type's
/// default. A double goes by its bits, so a negative zero, which
/// serializes, is set. `None` is a field the message does not have at all.
fn is_set<R: Runtime>(value: Option<&Val<'_, R>>) -> Result<bool, Error> {
    Ok(match value {
        None => false,
        Some(Val::Bool(b)) => *b,
        Some(Val::Int(i)) => *i != 0,
        Some(Val::Uint(u)) => *u != 0,
        Some(Val::Double(f)) => f.to_bits() != 0,
        Some(Val::Enum(e)) => *e != 0,
        Some(Val::String(s)) => !s.is_empty(),
        Some(Val::Bytes(b)) => !b.is_empty(),
        Some(Val::Message(_)) => true,
        Some(Val::List(list)) => list.len()? != 0,
        Some(Val::Map(map)) => map.len()? != 0,
    })
}

/// Whether a field is set: the runtime says for one that tracks presence,
/// its value for the rest.
fn has<R: Runtime>(message: &R::Message<'_>, field: &Field) -> Result<bool, Error> {
    if field.has_presence() {
        return Ok(message.has(field)?);
    }
    is_set(message.get(field)?.as_ref())
}

impl Key<'_> {
    fn is_empty(&self) -> bool {
        match self {
            Self::Bool(b) => !b,
            Self::Int(i) => *i == 0,
            Self::Uint(u) => *u == 0,
            Self::String(s) => s.is_empty(),
        }
    }

    #[cfg(feature = "cel")]
    fn scalar(&self) -> Scalar<'_> {
        match self {
            Self::Bool(b) => Scalar::Bool(*b),
            Self::Int(i) => Scalar::Int(*i),
            Self::Uint(u) => Scalar::Uint(*u),
            Self::String(s) => Scalar::String(s),
        }
    }

    fn subscript(&self) -> Subscript {
        match self {
            Self::Bool(b) => Subscript::BoolKey(*b),
            Self::Int(i) => Subscript::IntKey(*i),
            Self::Uint(u) => Subscript::UintKey(*u),
            Self::String(s) => Subscript::StringKey(s.to_string()),
        }
    }

    /// The key as a value, for the key rules.
    fn to_val<R: Runtime>(&self) -> Val<'_, R> {
        match self {
            Self::Bool(b) => Val::Bool(*b),
            Self::Int(i) => Val::Int(*i),
            Self::Uint(u) => Val::Uint(*u),
            Self::String(s) => Val::String(std::borrow::Cow::Borrowed(s)),
        }
    }
}

/// The CEL scalar for a field's value, or the type's zero when the message
/// does not have the field at all.
#[cfg(feature = "cel")]
fn scalar_of<'v, R: Runtime>(value: Option<&'v Val<'_, R>>, kind: ScalarKind) -> Scalar<'v> {
    match value {
        Some(Val::Bool(b)) => Scalar::Bool(*b),
        Some(Val::Int(i)) => Scalar::Int(*i),
        Some(Val::Uint(u)) => Scalar::Uint(*u),
        Some(Val::Double(f)) => Scalar::Double(*f),
        Some(Val::Enum(e)) => Scalar::Int(i64::from(*e)),
        Some(Val::String(s)) => Scalar::String(s),
        Some(Val::Bytes(b)) => Scalar::Bytes(b),
        Some(Val::Message(_) | Val::List(_) | Val::Map(_)) | None => match kind {
            ScalarKind::Bool => Scalar::Bool(false),
            ScalarKind::Int => Scalar::Int(0),
            ScalarKind::Uint => Scalar::Uint(0),
            ScalarKind::Double => Scalar::Double(0.0),
            ScalarKind::String => Scalar::String(""),
            ScalarKind::Bytes => Scalar::Bytes(&[]),
        },
    }
}

fn with_subscript(mut element: FieldPathElement, subscript: Subscript) -> FieldPathElement {
    element.subscript = Some(subscript);
    element
}

fn violation(
    rule_id: &str,
    message: &str,
    field: Option<&FieldPathElement>,
    rule: &[&FieldPathElement],
) -> Violation {
    Violation {
        field: field
            .map(|element| FieldPath {
                elements: vec![element.clone()],
                ..Default::default()
            })
            .into(),
        rule: (!rule.is_empty())
            .then(|| FieldPath {
                elements: rule.iter().map(|element| (*element).clone()).collect(),
                ..Default::default()
            })
            .into(),
        rule_id: Some(rule_id.to_owned()),
        message: Some(message.to_owned()),
        ..Default::default()
    }
}

/// One validation: the evaluators to use, and the violations found so far.
pub(crate) struct Walker<'a, R: Runtime> {
    pool: &'a DescriptorPool,
    schema: &'a Schema,
    #[cfg(feature = "cel")]
    env: &'a Env,
    evaluators: &'a HashMap<MessageIndex, Arc<MessageEvaluator>>,
    fail_fast: bool,
    violations: Vec<Violation>,
    runtime: PhantomData<R>,
}

impl<'a, R: Runtime> Walker<'a, R> {
    #[cfg(feature = "cel")]
    pub(crate) fn new(
        descriptors: &'a Descriptors,
        env: &'a Env,
        evaluators: &'a HashMap<MessageIndex, Arc<MessageEvaluator>>,
        fail_fast: bool,
    ) -> Self {
        Self {
            pool: &descriptors.pool,
            schema: &descriptors.schema,
            env,
            evaluators,
            fail_fast,
            violations: Vec::new(),
            runtime: PhantomData,
        }
    }

    #[cfg(not(feature = "cel"))]
    pub(crate) fn new(
        descriptors: &'a Descriptors,
        evaluators: &'a HashMap<MessageIndex, Arc<MessageEvaluator>>,
        fail_fast: bool,
    ) -> Self {
        Self {
            pool: &descriptors.pool,
            schema: &descriptors.schema,
            evaluators,
            fail_fast,
            violations: Vec::new(),
            runtime: PhantomData,
        }
    }

    /// Validates `message`, of type `type_name`, returning the violations.
    /// The message is serialized, for CEL, only if a rule needs it.
    pub(crate) fn validate(
        mut self,
        message: &R::Message<'_>,
        type_name: &str,
        evaluator: &MessageEvaluator,
    ) -> Result<Vec<Violation>, Error> {
        let encode = || message.encode();
        #[cfg(feature = "cel")]
        let frame = LazyFrame::root(self.env, type_name, &encode);
        #[cfg(not(feature = "cel"))]
        let frame = LazyFrame::root(type_name, &encode);
        self.message(message, &frame, evaluator)?;
        for violation in &mut self.violations {
            if let Some(field) = violation.field.as_option_mut() {
                field.elements.reverse();
            }
            if let Some(rule) = violation.rule.as_option_mut() {
                rule.elements.reverse();
            }
        }
        Ok(self.violations)
    }

    /// Whether to stop: failing fast, with a violation found.
    fn should_return(&self) -> bool {
        self.fail_fast && !self.violations.is_empty()
    }

    fn append_field(&mut self, from: usize, element: &FieldPathElement) {
        for violation in &mut self.violations[from..] {
            violation
                .field
                .get_or_insert_default()
                .elements
                .push(element.clone());
        }
    }

    fn append_rule(&mut self, from: usize, elements: &[FieldPathElement]) {
        for violation in &mut self.violations[from..] {
            violation
                .rule
                .get_or_insert_default()
                .elements
                .extend(elements.iter().cloned());
        }
    }

    fn mark_for_key(&mut self, from: usize) {
        for violation in &mut self.violations[from..] {
            violation.for_key = Some(true);
        }
    }

    /// Runs the standard rules against a value, stopping at the first
    /// violation when failing fast. A wrapper message is checked by its
    /// `value` field, as CEL unboxes it.
    fn checks(
        &mut self,
        checks: &[Check],
        wrapper: Option<&Field>,
        value: Option<&Val<'_, R>>,
    ) -> Result<(), Error> {
        if let Some(wrapper) = wrapper {
            let unboxed = match value {
                Some(Val::Message(message)) => message.get(wrapper)?,
                _ => None,
            };
            self.run_checks(checks, unboxed.as_ref())
        } else {
            self.run_checks(checks, value)
        }
    }

    fn run_checks(&mut self, checks: &[Check], value: Option<&Val<'_, R>>) -> Result<(), Error> {
        for check in checks {
            if check.test.fails(value)? {
                self.violations.push(violation(
                    &check.id,
                    &check.message,
                    None,
                    &[&check.rule_path[0], &check.rule_path[1]],
                ));
                if self.fail_fast {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Runs each expression against `this`, recording its failures as
    /// violations. One passes by producing `true` or an empty string;
    /// `false` fails with the rule's own message, and a non-empty string
    /// fails with that string as the message.
    #[cfg(feature = "cel")]
    fn run(&mut self, programs: &ProgramSet, this: This<'_>) -> Result<(), Error> {
        for (index, meta) in programs.rules.iter().enumerate() {
            let message = match programs.program.eval(index, this)? {
                Value::Bool(true) => continue,
                Value::Bool(false) if meta.message.is_empty() => {
                    format!("\"{}\" returned false", meta.expression)
                }
                Value::Bool(false) => meta.message.clone(),
                Value::String(text) if text.is_empty() => continue,
                Value::String(text) => text,
                Value::Other => {
                    return Err(Error::Evaluation("invalid result type".to_owned()));
                }
            };
            let rule: Vec<&FieldPathElement> = meta.rule_path.iter().collect();
            self.violations
                .push(violation(&meta.id, &message, None, &rule));
            if self.fail_fast {
                break;
            }
        }
        Ok(())
    }

    fn message(
        &mut self,
        message: &R::Message<'_>,
        frame: &LazyFrame<'_>,
        evaluator: &MessageEvaluator,
    ) -> Result<(), Error> {
        #[cfg(feature = "cel")]
        if let Some(programs) = &evaluator.cel {
            let this = This::Message(frame.parsed()?);
            self.run(programs, this)?;
            if self.should_return() {
                return Ok(());
            }
        }
        for oneof in &evaluator.message_oneofs {
            self.message_oneof(message, oneof)?;
            if self.should_return() {
                return Ok(());
            }
        }
        for field in &evaluator.fields {
            self.field(message, frame, field)?;
            if self.should_return() {
                return Ok(());
            }
        }
        for oneof in &evaluator.oneofs {
            self.oneof(message, oneof)?;
            if self.should_return() {
                return Ok(());
            }
        }
        self.nested(message, frame, evaluator)
    }

    fn message_oneof(
        &mut self,
        message: &R::Message<'_>,
        oneof: &MessageOneof,
    ) -> Result<(), Error> {
        let mut set = 0;
        for field in &oneof.fields {
            if has::<R>(message, field)? {
                set += 1;
            }
        }
        if set > 1 {
            self.violations.push(violation(
                "message.oneof",
                &format!("only one of {} can be set", oneof.names),
                None,
                &[],
            ));
        }
        if oneof.required && set == 0 {
            self.violations.push(violation(
                "message.oneof",
                &format!("one of {} must be set", oneof.names),
                None,
                &[],
            ));
        }
        Ok(())
    }

    fn oneof(&mut self, message: &R::Message<'_>, oneof: &OneofRequired) -> Result<(), Error> {
        for member in &oneof.members {
            if has::<R>(message, member)? {
                return Ok(());
            }
        }
        self.violations.push(violation(
            "required",
            "exactly one field is required in oneof",
            Some(&oneof.element),
            &[],
        ));
        Ok(())
    }

    fn required(&mut self, field: &FieldEvaluator) {
        self.violations.push(violation(
            "required",
            "value is required",
            Some(&field.element),
            &[&self.schema.required],
        ));
    }

    fn any(
        &mut self,
        field: Option<&FieldPathElement>,
        any: &R::Message<'_>,
        check: &AnyCheck,
    ) -> Result<(), Error> {
        let type_url = any.get(&descriptors::wkt::ANY_TYPE_URL)?;
        let type_url = match &type_url {
            Some(Val::String(url)) => url.as_ref(),
            _ => "",
        };
        if !check.r#in.is_empty() && !check.r#in.iter().any(|allowed| allowed == type_url) {
            self.violations.push(violation(
                "any.in",
                "type URL must be in the allow list",
                field,
                &[&self.schema.any_in, &self.schema.any],
            ));
        }
        if check.not_in.iter().any(|blocked| blocked == type_url) {
            self.violations.push(violation(
                "any.not_in",
                "type URL must not be in the block list",
                field,
                &[&self.schema.any_not_in, &self.schema.any],
            ));
        }
        Ok(())
    }

    /// The rules of one field: presence, the checks and CEL programs, then
    /// the enum, repeated and map rules.
    fn field(
        &mut self,
        message: &R::Message<'_>,
        frame: &LazyFrame<'_>,
        field: &FieldEvaluator,
    ) -> Result<(), Error> {
        let value = message.get(&field.field)?;
        match field.shape {
            Shape::List | Shape::Map { .. } => {
                let len = match &value {
                    Some(Val::List(list)) => list.len()?,
                    Some(Val::Map(map)) => map.len()?,
                    _ => 0,
                };
                if len == 0 {
                    if field.rules.ignore_empty {
                        return Ok(());
                    }
                    if field.required {
                        self.required(field);
                        return Ok(());
                    }
                }
            }
            Shape::Singular => {
                let set = if field.field.has_presence() {
                    message.has(&field.field)?
                } else {
                    is_set(value.as_ref())?
                };
                if !set {
                    if field.required {
                        self.required(field);
                        return Ok(());
                    }
                    if field.rules.ignore_empty {
                        return Ok(());
                    }
                }
                if let (Some(check), Some(Val::Message(any))) = (&field.rules.any, &value) {
                    self.any(Some(&field.element), any, check)?;
                }
            }
        }

        let from = self.violations.len();
        self.checks(
            &field.rules.checks,
            field.rules.wrapper.as_ref(),
            value.as_ref(),
        )?;
        #[cfg(feature = "cel")]
        if let Some(programs) = &field.rules.programs {
            if !self.should_return() {
                // CEL only sees the message if a custom rule needs it.
                let this = match (field.shape, field.rules.scalar) {
                    (Shape::Singular, Some(kind)) => This::Scalar(scalar_of(value.as_ref(), kind)),
                    _ => This::Field(frame.parsed()?, field_number(field.field.number())),
                };
                self.run(programs, this)?;
            }
        }
        if self.violations.len() > from {
            self.append_field(from, &field.element);
        }

        if let Some(enum_index) = field.defined_only {
            if self.should_return() {
                return Ok(());
            }
            if let Some(Val::Enum(number)) = &value {
                if self.pool.enumeration(enum_index).value(*number).is_none() {
                    self.violations.push(violation(
                        "enum.defined_only",
                        "value must be one of the defined enum values",
                        Some(&field.element),
                        &[&self.schema.enum_defined_only, &self.schema.r#enum],
                    ));
                }
            }
        }

        if let Some(items) = &field.items {
            if self.should_return() {
                return Ok(());
            }
            if let Some(Val::List(list)) = &value {
                self.items(frame, field, items, list)?;
            }
        }

        if field.keys.is_some() || field.values.is_some() {
            if let Some(Val::Map(map)) = &value {
                self.map(frame, field, map)?;
            }
        }
        Ok(())
    }

    /// The rules of one element or map value: the checks, then the custom
    /// CEL with `this` bound to the value -- a scalar directly, a message
    /// through a frame of its own.
    // `frame` and `field` are only for CEL.
    #[cfg_attr(not(feature = "cel"), expect(unused_variables))]
    #[inline]
    fn item(
        &mut self,
        rules: &ValueRules,
        frame: &LazyFrame<'_>,
        field: &Field,
        value: &Val<'_, R>,
    ) -> Result<(), Error> {
        self.checks(&rules.checks, rules.wrapper.as_ref(), Some(value))?;
        #[cfg(feature = "cel")]
        if let Some(programs) = &rules.programs {
            if !self.should_return() {
                match (rules.scalar, value) {
                    (Some(kind), _) => {
                        self.run(programs, This::Scalar(scalar_of(Some(value), kind)))?;
                    }
                    (None, Val::Message(sub)) => {
                        let encode = || sub.encode();
                        let child = LazyFrame::child(frame, message_type(field)?, &encode);
                        self.run(programs, This::Message(child.parsed()?))?;
                    }
                    (None, _) => {
                        return Err(Error::Unexpected(format!(
                            "{} holds no message to bind this to",
                            field.name()
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    fn items(
        &mut self,
        frame: &LazyFrame<'_>,
        field: &FieldEvaluator,
        items: &ItemEvaluator,
        list: &R::List<'_>,
    ) -> Result<(), Error> {
        for index in 0..list.len()? {
            let Some(item) = list.get(index)? else {
                continue;
            };
            if items.rules.ignore_empty && is_empty_item(&item) {
                continue;
            }
            let from = self.violations.len();
            self.item(&items.rules, frame, &field.field, &item)?;
            if let (Some(check), Val::Message(any)) = (&items.rules.any, &item) {
                self.any(None, any, check)?;
            }
            if self.violations.len() > from {
                let element = with_subscript(field.element.clone(), Subscript::Index(index as u64));
                self.append_field(from, &element);
                self.append_rule(from, &items.rule_prefix);
            }
            if self.should_return() {
                return Ok(());
            }
        }
        Ok(())
    }

    fn map(
        &mut self,
        frame: &LazyFrame<'_>,
        field: &FieldEvaluator,
        map: &R::Map<'_>,
    ) -> Result<(), Error> {
        let mut result = Ok(());
        map.for_each(
            &mut |key, value| match self.map_entry(frame, field, &key, &value) {
                Ok(true) => ControlFlow::Continue(()),
                Ok(false) => ControlFlow::Break(()),
                Err(error) => {
                    result = Err(error);
                    ControlFlow::Break(())
                }
            },
        )?;
        result
    }

    /// One map entry; `Ok(false)` when fail-fast stops the walk over the map.
    fn map_entry(
        &mut self,
        frame: &LazyFrame<'_>,
        field: &FieldEvaluator,
        key: &Key<'_>,
        value: &Val<'_, R>,
    ) -> Result<bool, Error> {
        let from = self.violations.len();
        if let Some(keys) = &field.keys {
            if !(keys.rules.ignore_empty && key.is_empty()) {
                self.checks(&keys.rules.checks, None, Some(&key.to_val()))?;
                #[cfg(feature = "cel")]
                if let Some(programs) = &keys.rules.programs {
                    if !self.should_return() {
                        self.run(programs, This::Scalar(key.scalar()))?;
                    }
                }
                if self.violations.len() > from {
                    self.append_rule(from, &keys.rule_prefix);
                    self.mark_for_key(from);
                }
            }
        }
        if let Some(values) = &field.values {
            if !(values.rules.ignore_empty && is_empty_item(value)) {
                let value_from = self.violations.len();
                self.item(&values.rules, frame, &field.field, value)?;
                if self.violations.len() > value_from {
                    self.append_rule(value_from, &values.rule_prefix);
                }
            }
        }
        if self.violations.len() > from {
            let template = field.entry_element.as_ref().unwrap_or(&field.element);
            let element = with_subscript(template.clone(), key.subscript());
            self.append_field(from, &element);
            if self.fail_fast {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Validates every set message-typed field, in field-number order.
    fn nested(
        &mut self,
        message: &R::Message<'_>,
        frame: &LazyFrame<'_>,
        evaluator: &MessageEvaluator,
    ) -> Result<(), Error> {
        for nested in &evaluator.nested {
            if nested.shape == Shape::Singular && !message.has(&nested.field)? {
                continue;
            }
            let Some(value) = message.get(&nested.field)? else {
                continue;
            };
            let Some(sub_evaluator) = self.evaluators.get(&nested.message) else {
                return Err(Error::Unexpected(format!(
                    "rules not loaded for message: {}",
                    self.pool.message(nested.message).full_name()
                )));
            };
            let type_name = message_type(&nested.field)?;
            match (nested.shape, &value) {
                (Shape::Singular, Val::Message(sub)) => {
                    self.nested_message(sub, frame, type_name, sub_evaluator, || {
                        nested.element.clone()
                    })?;
                }
                (Shape::List, Val::List(list)) => {
                    for index in 0..list.len()? {
                        let Some(Val::Message(sub)) = list.get(index)? else {
                            continue;
                        };
                        self.nested_message(&sub, frame, type_name, sub_evaluator, || {
                            with_subscript(nested.element.clone(), Subscript::Index(index as u64))
                        })?;
                        if self.should_return() {
                            return Ok(());
                        }
                    }
                }
                (Shape::Map { .. }, Val::Map(map)) => {
                    let mut result = Ok(());
                    map.for_each(&mut |key, item| {
                        let Val::Message(sub) = &item else {
                            return ControlFlow::Continue(());
                        };
                        if let Err(error) =
                            self.nested_message(sub, frame, type_name, sub_evaluator, || {
                                with_subscript(nested.element.clone(), key.subscript())
                            })
                        {
                            result = Err(error);
                            return ControlFlow::Break(());
                        }
                        if self.should_return() {
                            ControlFlow::Break(())
                        } else {
                            ControlFlow::Continue(())
                        }
                    })?;
                    result?;
                }
                _ => {}
            }
            if self.should_return() {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Validates a message the walk descends into, appending the path
    /// element it was reached by -- built only then -- to the paths of the
    /// violations it adds.
    #[inline]
    fn nested_message(
        &mut self,
        sub: &R::Message<'_>,
        frame: &LazyFrame<'_>,
        type_name: &str,
        evaluator: &MessageEvaluator,
        element: impl FnOnce() -> FieldPathElement,
    ) -> Result<(), Error> {
        let encode = || sub.encode();
        let child = LazyFrame::child(frame, type_name, &encode);
        let from = self.violations.len();
        self.message(sub, &child, evaluator)?;
        if self.violations.len() > from {
            self.append_field(from, &element());
        }
        Ok(())
    }
}
