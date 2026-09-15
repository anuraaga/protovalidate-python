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

//! The validator's view of a live Python message.
//!
//! [`PyRuntime`] implements the `protovalidate` reflection traits over
//! protobuf-py and google.protobuf message objects, so a message is
//! validated in place: the fields the rules need are read through the
//! Python object, and the message is only serialized if a CEL rule binds
//! the message itself, a repeated field or a map to `this`.
//!
//! The validator describes each field it asks for, so what is left to know
//! is runtime-specific: the attribute a field is read from, and when it
//! counts as set, which [`TypeInfo`] records once per message class. The
//! traits have no error channel, so the first Python error is kept on the
//! [`Ctx`] and raised once validation returns.

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::{Arc, RwLock};

use protovalidate::protobuf::{
    Field, Key, Kind, List, Map, Message, Payload, Runtime, Scalar, Singular, Val,
};
use protovalidate::{Error, Validator};
use pyo3::prelude::*;
use pyo3::sync::RwLockExt;
use pyo3::types::{PyBytes, PyDict, PyList, PyString, PyType};

use crate::constants::Constants;
use crate::proto::ProtoRuntime;

/// The Python runtimes, as the validator reads them.
pub(crate) struct PyRuntime;

impl Runtime for PyRuntime {
    type Message<'a> = MessageView<'a>;
    type List<'a> = ListView<'a>;
    type Map<'a> = MapView<'a>;
}

/// Where a message class keeps its fields, built once per class.
pub(crate) struct TypeInfo {
    /// Sorted by field number.
    fields: Vec<FieldInfo>,
}

struct FieldInfo {
    number: u32,
    /// The attribute holding the value: the proto name for google.protobuf,
    /// the Python-local name for protobuf-py.
    attr: Py<PyString>,
    /// For a protobuf-py field in a oneof, the oneof's attribute and the
    /// field's proto name as the `Oneof` value reports it.
    oneof: Option<(Py<PyString>, Py<PyString>)>,
}

/// When a field counts as set.
#[derive(Clone, Copy)]
enum Presence {
    /// google.protobuf tracks it: `HasField`.
    HasField,
    /// protobuf-py tracks it in the message's `_present` set.
    Tracked,
    /// protobuf-py oneof member: set when the oneof selects it.
    Oneof,
    /// Derived from the value: non-default scalar, non-`None` message,
    /// non-empty list or map.
    Value,
}

impl TypeInfo {
    fn build(ctx: &Ctx<'_>, class: &Bound<'_, PyType>) -> PyResult<Self> {
        let constants = ctx.constants;
        let intern = |name: Bound<'_, PyAny>| -> PyResult<Py<PyString>> {
            let name = name.cast_into::<PyString>()?;
            Ok(PyString::intern(ctx.py, name.to_str()?).unbind())
        };
        let mut fields = Vec::new();
        match ctx.runtime {
            ProtoRuntime::Google => {
                let descriptor = class.getattr(&constants.descriptor_upper)?;
                for field in descriptor.getattr(&constants.fields)?.try_iter()? {
                    let field = field?;
                    fields.push(FieldInfo {
                        number: field.getattr(&constants.number)?.extract()?,
                        attr: intern(field.getattr(&constants.name)?)?,
                        oneof: None,
                    });
                }
            }
            ProtoRuntime::ProtobufPy => {
                let desc = class.call_method0(&constants.desc)?;
                for field in desc.getattr(&constants.fields)?.try_iter()? {
                    let field = field?;
                    // Only a singular value has a `oneof`, and it is `None`
                    // for a proto3 `optional` field, whose synthetic oneof
                    // protobuf-py does not surface: such a field is stored
                    // like any other.
                    let oneof = match field.getattr(&constants.value)?.getattr(&constants.oneof) {
                        Ok(oneof) if !oneof.is_none() => Some((
                            intern(oneof.getattr(&constants.local_name)?)?,
                            intern(field.getattr(&constants.name)?)?,
                        )),
                        _ => None,
                    };
                    fields.push(FieldInfo {
                        number: field.getattr(&constants.number)?.extract()?,
                        attr: intern(field.getattr(&constants.local_name)?)?,
                        oneof,
                    });
                }
            }
        }
        fields.sort_by_key(|field| field.number);
        Ok(Self { fields })
    }

    fn find(&self, number: u32) -> Option<(usize, &FieldInfo)> {
        let slot = self
            .fields
            .binary_search_by_key(&number, |field| field.number)
            .ok()?;
        Some((slot, &self.fields[slot]))
    }
}

/// The type information of every message class read so far, by the class's
/// address.
#[derive(Default)]
pub(crate) struct TypeCache(RwLock<HashMap<usize, CachedType>>);

/// A class's type information, with the class kept alive so its address
/// stays its own.
struct CachedType {
    _class: Py<PyType>,
    info: Arc<TypeInfo>,
}

/// Everything a view needs besides its object, for the duration of one
/// validation.
pub(crate) struct Ctx<'py> {
    py: Python<'py>,
    runtime: ProtoRuntime,
    types: &'py TypeCache,
    constants: &'py Constants,
    /// The first Python error raised while reading the message.
    error: RefCell<Option<PyErr>>,
}

impl<'py> Ctx<'py> {
    pub(crate) fn new(
        py: Python<'py>,
        runtime: ProtoRuntime,
        types: &'py TypeCache,
        constants: &'py Constants,
    ) -> Self {
        Self {
            py,
            runtime,
            types,
            constants,
            error: RefCell::new(None),
        }
    }

    /// Validates `message`, of type `type_name`, in place.
    ///
    /// A Python error raised while reading the message takes precedence
    /// over the validation result.
    pub(crate) fn validate(
        &self,
        validator: &Validator,
        type_name: &str,
        message: &Bound<'py, PyAny>,
        fail_fast: bool,
    ) -> PyResult<Result<(), Error>> {
        let root = MessageView::new(self, message.clone());
        let encode = || self.serialize(message);
        let result = validator.validate_message::<PyRuntime>(
            type_name,
            &root,
            Payload::Encode(&encode),
            fail_fast,
        );
        match self.error.take() {
            Some(error) => Err(error),
            None => Ok(result),
        }
    }

    /// The serialized message, for CEL.
    fn serialize(&self, message: &Bound<'py, PyAny>) -> Vec<u8> {
        self.ok(self.runtime.payload(message, self.constants))
            .map(|bytes| bytes.as_bytes().to_vec())
            .unwrap_or_default()
    }

    /// Unwraps a Python result, keeping the first error for `validate`.
    fn ok<T>(&self, result: PyResult<T>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.error.borrow_mut().get_or_insert(error);
                None
            }
        }
    }

    /// The type information of `object`'s class, built on first use.
    fn type_info(&self, object: &Bound<'py, PyAny>) -> Option<Arc<TypeInfo>> {
        let class = object.get_type();
        let key = class.as_ptr().addr();
        if let Some(cached) = self.types.0.read_py_attached(self.py).unwrap().get(&key) {
            return Some(Arc::clone(&cached.info));
        }
        let info = Arc::new(self.ok(TypeInfo::build(self, &class))?);
        let mut types = self.types.0.write_py_attached(self.py).unwrap();
        let cached = types.entry(key).or_insert(CachedType {
            _class: class.unbind(),
            info,
        });
        Some(Arc::clone(&cached.info))
    }
}

/// A message, read through its Python object.
pub(crate) struct MessageView<'a> {
    ctx: &'a Ctx<'a>,
    /// `None` for a protobuf-py message field that is not set, which reads
    /// as a message with nothing set; also `None` when building the type
    /// information failed.
    info: Option<Arc<TypeInfo>>,
    object: Bound<'a, PyAny>,
    /// Field values already fetched, by position in `info.fields`, so a
    /// value is read once and borrowed from for as long as the view lives.
    slots: Box<[OnceCell<Option<Bound<'a, PyAny>>>]>,
}

impl<'a> MessageView<'a> {
    fn new(ctx: &'a Ctx<'a>, object: Bound<'a, PyAny>) -> Self {
        let info = if object.is_none() {
            None
        } else {
            ctx.type_info(&object)
        };
        let slots = info.as_ref().map_or(0, |info| info.fields.len());
        Self {
            ctx,
            info,
            object,
            slots: std::iter::repeat_with(OnceCell::new).take(slots).collect(),
        }
    }

    /// The field's value, `None` when it is not set and the runtime has no
    /// default object for it: a protobuf-py message field, or a oneof
    /// member the oneof does not select.
    fn value(&self, slot: usize, field: &FieldInfo) -> Option<&Bound<'a, PyAny>> {
        self.slots[slot]
            .get_or_init(|| self.ctx.ok(self.fetch(field)).flatten())
            .as_ref()
    }

    fn fetch(&self, field: &FieldInfo) -> PyResult<Option<Bound<'a, PyAny>>> {
        let constants = self.ctx.constants;
        if let Some((oneof, name)) = &field.oneof {
            let selected = self.object.getattr(oneof)?;
            if selected.is_none() {
                return Ok(None);
            }
            if !selected.getattr(&constants.field)?.eq(name)? {
                return Ok(None);
            }
            return Ok(Some(selected.getattr(&constants.value)?));
        }
        let value = self.object.getattr(&field.attr)?;
        Ok((!value.is_none()).then_some(value))
    }

    fn has_field(&self, field: &FieldInfo) -> PyResult<bool> {
        let constants = self.ctx.constants;
        self.object
            .call_method1(&constants.has_field, (&field.attr,))?
            .extract()
    }

    fn tracked(&self, field: &FieldInfo) -> PyResult<bool> {
        self.object
            .getattr(&self.ctx.constants.present)?
            .contains(field.number)
    }

    /// When the field counts as set, by the runtime and what the validator
    /// says of the field.
    fn presence(&self, field: &Field, stored: &FieldInfo) -> Presence {
        match self.ctx.runtime {
            ProtoRuntime::Google => match field.kind() {
                Kind::Singular(Singular::Message) => Presence::HasField,
                Kind::Singular(_) if field.has_presence() => Presence::HasField,
                _ => Presence::Value,
            },
            ProtoRuntime::ProtobufPy => match field.kind() {
                _ if stored.oneof.is_some() => Presence::Oneof,
                Kind::Singular(Singular::Message) => Presence::Value,
                Kind::Singular(_) if field.has_presence() => Presence::Tracked,
                _ => Presence::Value,
            },
        }
    }
}

impl Message<PyRuntime> for MessageView<'_> {
    fn encode(&self) -> Vec<u8> {
        // An unset protobuf-py message field is `None`, and reads as a
        // message with nothing set, which encodes to nothing.
        if self.object.is_none() {
            return Vec::new();
        }
        self.ctx.serialize(&self.object)
    }

    fn has(&self, field: &Field) -> bool {
        let Some(info) = &self.info else {
            return false;
        };
        let Some((slot, stored)) = info.find(field.number()) else {
            return false;
        };
        match self.presence(field, stored) {
            Presence::HasField => self.ctx.ok(self.has_field(stored)).unwrap_or(false),
            Presence::Tracked => self.ctx.ok(self.tracked(stored)).unwrap_or(false),
            Presence::Oneof => self.value(slot, stored).is_some(),
            Presence::Value => match self.value(slot, stored) {
                Some(value) => self.ctx.ok(is_set(field.kind(), value)).unwrap_or(false),
                None => false,
            },
        }
    }

    fn get(&self, field: &Field) -> Option<Val<'_, PyRuntime>> {
        let Some(info) = &self.info else {
            // Nothing is set: every field reads as its default.
            return Some(convert(self.ctx, field.kind(), None));
        };
        let (slot, stored) = info.find(field.number())?;
        Some(convert(self.ctx, field.kind(), self.value(slot, stored)))
    }
}

/// Whether a value counts as set for a field without tracked presence.
fn is_set(kind: Kind, value: &Bound<'_, PyAny>) -> PyResult<bool> {
    match kind {
        Kind::Singular(Singular::Message) => Ok(!value.is_none()),
        Kind::Singular(Singular::Enum) => Ok(value.extract::<i32>()? != 0),
        Kind::Singular(Singular::Scalar(scalar)) => match scalar {
            Scalar::Bool => value.extract(),
            Scalar::Float | Scalar::Double => Ok(value.extract::<f64>()?.to_bits() != 0),
            Scalar::String | Scalar::Bytes => Ok(value.len()? != 0),
            // Signed or unsigned, zero is zero either way.
            _ => Ok(value
                .extract::<i64>()
                .or_else(|_| value.extract::<u64>().map(u64::cast_signed))?
                != 0),
        },
        Kind::List(_) | Kind::Map { .. } => Ok(value.len()? != 0),
    }
}

/// A field's value as the validator sees it; the default when `value` is
/// `None`.
fn convert<'a>(
    ctx: &'a Ctx<'a>,
    kind: Kind,
    value: Option<&'a Bound<'a, PyAny>>,
) -> Val<'a, PyRuntime> {
    match kind {
        Kind::Singular(kind) => singular(ctx, kind, value),
        Kind::List(element) => Val::List(ListView {
            ctx,
            element,
            object: value,
            items: OnceCell::new(),
        }),
        Kind::Map {
            key,
            value: element,
        } => Val::Map(MapView {
            ctx,
            key,
            element,
            object: value,
        }),
    }
}

fn singular<'a>(
    ctx: &'a Ctx<'a>,
    kind: Singular,
    value: Option<&'a Bound<'a, PyAny>>,
) -> Val<'a, PyRuntime> {
    match kind {
        Singular::Message => Val::Message(MessageView::new(
            ctx,
            value
                .cloned()
                .unwrap_or_else(|| ctx.py.None().into_bound(ctx.py)),
        )),
        Singular::Enum => Val::Enum(
            value
                .and_then(|value| ctx.ok(value.extract::<i32>()))
                .unwrap_or_default(),
        ),
        Singular::Scalar(scalar) => match value {
            Some(value) => scalar_value(ctx, scalar, value),
            None => default(scalar),
        },
    }
}

fn scalar_value<'a>(
    ctx: &'a Ctx<'a>,
    scalar: Scalar,
    value: &'a Bound<'a, PyAny>,
) -> Val<'a, PyRuntime> {
    match scalar {
        Scalar::Bool => Val::Bool(ctx.ok(value.extract()).unwrap_or_default()),
        Scalar::Int32
        | Scalar::Int64
        | Scalar::Sint32
        | Scalar::Sint64
        | Scalar::Sfixed32
        | Scalar::Sfixed64 => Val::Int(ctx.ok(value.extract()).unwrap_or_default()),
        Scalar::Uint32 | Scalar::Uint64 | Scalar::Fixed32 | Scalar::Fixed64 => {
            Val::Uint(ctx.ok(value.extract()).unwrap_or_default())
        }
        Scalar::Float | Scalar::Double => Val::Double(ctx.ok(value.extract()).unwrap_or_default()),
        Scalar::String => Val::String(
            ctx.ok(value
                .cast::<PyString>()
                .map_err(PyErr::from)
                .and_then(|s| s.to_str()))
                .unwrap_or_default()
                .into(),
        ),
        Scalar::Bytes => Val::Bytes(
            ctx.ok(value.cast::<PyBytes>().map_err(PyErr::from))
                .map(pyo3::types::PyBytesMethods::as_bytes)
                .unwrap_or_default()
                .into(),
        ),
    }
}

fn default<'a>(scalar: Scalar) -> Val<'a, PyRuntime> {
    match scalar {
        Scalar::Bool => Val::Bool(false),
        Scalar::Int32
        | Scalar::Int64
        | Scalar::Sint32
        | Scalar::Sint64
        | Scalar::Sfixed32
        | Scalar::Sfixed64 => Val::Int(0),
        Scalar::Uint32 | Scalar::Uint64 | Scalar::Fixed32 | Scalar::Fixed64 => Val::Uint(0),
        Scalar::Float | Scalar::Double => Val::Double(0.0),
        Scalar::String => Val::String("".into()),
        Scalar::Bytes => Val::Bytes((&[][..]).into()),
    }
}

fn key<'a>(ctx: &'a Ctx<'a>, scalar: Scalar, value: &'a Bound<'a, PyAny>) -> Key<'a> {
    match scalar_value(ctx, scalar, value) {
        Val::Bool(b) => Key::Bool(b),
        Val::Int(i) => Key::Int(i),
        Val::Uint(u) => Key::Uint(u),
        Val::String(s) => Key::String(s),
        // Not valid map key types; the validator's descriptors reject them.
        Val::Double(_)
        | Val::Enum(_)
        | Val::Bytes(_)
        | Val::Message(_)
        | Val::List(_)
        | Val::Map(_) => Key::Int(0),
    }
}

/// A repeated field: a `list` for protobuf-py, a repeated container for
/// google.protobuf.
pub(crate) struct ListView<'a> {
    ctx: &'a Ctx<'a>,
    element: Singular,
    /// `None` for an unset field, which is empty.
    object: Option<&'a Bound<'a, PyAny>>,
    /// The elements, fetched all at once on first access: a google.protobuf
    /// container hands out a new object per access, so they are held here
    /// for values to borrow from.
    items: OnceCell<Vec<Bound<'a, PyAny>>>,
}

impl<'a> ListView<'a> {
    fn items(&self) -> &[Bound<'a, PyAny>] {
        self.items.get_or_init(|| {
            let Some(object) = self.object else {
                return Vec::new();
            };
            let items = match object.cast::<PyList>() {
                Ok(list) => Ok(list.iter().collect()),
                Err(_) => object
                    .try_iter()
                    .and_then(Iterator::collect::<PyResult<Vec<_>>>),
            };
            self.ctx.ok(items).unwrap_or_default()
        })
    }
}

impl List<PyRuntime> for ListView<'_> {
    fn len(&self) -> usize {
        match self.items.get() {
            Some(items) => items.len(),
            None => self
                .object
                .and_then(|object| self.ctx.ok(object.len()))
                .unwrap_or(0),
        }
    }

    fn get(&self, index: usize) -> Option<Val<'_, PyRuntime>> {
        let item = self.items().get(index)?;
        Some(singular(self.ctx, self.element, Some(item)))
    }
}

/// A map field: a `dict` for protobuf-py, a map container for
/// google.protobuf.
pub(crate) struct MapView<'a> {
    ctx: &'a Ctx<'a>,
    key: Scalar,
    element: Singular,
    /// `None` for an unset field, which is empty.
    object: Option<&'a Bound<'a, PyAny>>,
}

impl Map<PyRuntime> for MapView<'_> {
    fn len(&self) -> usize {
        self.object
            .and_then(|object| self.ctx.ok(object.len()))
            .unwrap_or(0)
    }

    fn for_each(&self, f: &mut dyn FnMut(Key<'_>, Val<'_, PyRuntime>) -> ControlFlow<()>) {
        let Some(object) = self.object else {
            return;
        };
        if let Ok(dict) = object.cast::<PyDict>() {
            for (k, v) in dict.iter() {
                let flow = f(
                    key(self.ctx, self.key, &k),
                    singular(self.ctx, self.element, Some(&v)),
                );
                if flow.is_break() {
                    return;
                }
            }
            return;
        }
        let entries = object
            .call_method0(&self.ctx.constants.items)
            .and_then(|items| items.try_iter());
        let Some(entries) = self.ctx.ok(entries) else {
            return;
        };
        for entry in entries {
            let Some((k, v)) =
                self.ctx
                    .ok(entry
                        .and_then(|entry| entry.extract::<(Bound<'_, PyAny>, Bound<'_, PyAny>)>()))
            else {
                return;
            };
            let flow = f(
                key(self.ctx, self.key, &k),
                singular(self.ctx, self.element, Some(&v)),
            );
            if flow.is_break() {
                return;
            }
        }
    }
}
