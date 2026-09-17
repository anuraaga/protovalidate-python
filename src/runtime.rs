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
//! is runtime-specific: the attribute a field is read from, and how the
//! runtime tracks that it is set, which [`TypeInfo`] records once per
//! message class. A Python error raised while reading goes back through
//! the validator as a `ReadError`, and is raised again from the call.

// The value chain -- the trait's `get`s through `convert`, `singular` and
// `scalar_value` -- has to be inlined into the walk. Left to the optimizer
// it is not, and element-heavy messages validate 5-12% slower; `#[inline]`
// alone does not do it. Measured with the throughput loop in the
// benchmarks, not assumed.
#![allow(clippy::inline_always)]

use std::cell::OnceCell;
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::{Arc, RwLock};

use protovalidate::protobuf::{
    Field, Key, Kind, List, Map, Message, ReadError, Runtime, Scalar, Singular, Val,
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

impl TypeInfo {
    fn build(ctx: &Ctx<'_>, class: &Bound<'_, PyType>) -> Result<Self, ReadError> {
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
        }
    }

    /// Validates `message`, of type `type_name`, in place.
    pub(crate) fn validate(
        &self,
        validator: &Validator,
        type_name: &str,
        message: &Bound<'py, PyAny>,
        fail_fast: bool,
    ) -> Result<(), Error> {
        let root = MessageView::new(self, message.clone())?;
        validator.validate_message::<PyRuntime>(type_name, &root, fail_fast)
    }

    /// The serialized message, for CEL.
    fn serialize(&self, message: &Bound<'py, PyAny>) -> Result<Vec<u8>, ReadError> {
        Ok(self
            .runtime
            .payload(message, self.constants)?
            .as_bytes()
            .to_vec())
    }

    /// The type information of `object`'s class, built on first use.
    fn type_info(&self, object: &Bound<'py, PyAny>) -> Result<Arc<TypeInfo>, ReadError> {
        let class = object.get_type();
        let key = class.as_ptr().addr();
        if let Some(cached) = self.types.0.read_py_attached(self.py).unwrap().get(&key) {
            return Ok(Arc::clone(&cached.info));
        }
        let info = Arc::new(TypeInfo::build(self, &class)?);
        let mut types = self.types.0.write_py_attached(self.py).unwrap();
        let cached = types.entry(key).or_insert(CachedType {
            _class: class.unbind(),
            info,
        });
        Ok(Arc::clone(&cached.info))
    }
}

/// A message, read through its Python object.
pub(crate) struct MessageView<'a> {
    ctx: &'a Ctx<'a>,
    /// `None` for a protobuf-py message field that is not set, which reads
    /// as a message with nothing set.
    info: Option<Arc<TypeInfo>>,
    object: Bound<'a, PyAny>,
    /// Field values already fetched, by position in `info.fields`, so a
    /// value is read once and borrowed from for as long as the view lives.
    slots: Box<[OnceCell<Option<Bound<'a, PyAny>>>]>,
}

impl<'a> MessageView<'a> {
    fn new(ctx: &'a Ctx<'a>, object: Bound<'a, PyAny>) -> Result<Self, ReadError> {
        let info = if object.is_none() {
            None
        } else {
            Some(ctx.type_info(&object)?)
        };
        let slots = info.as_ref().map_or(0, |info| info.fields.len());
        Ok(Self {
            ctx,
            info,
            object,
            slots: std::iter::repeat_with(OnceCell::new).take(slots).collect(),
        })
    }

    /// The field's value, `None` when it is not set and the runtime has no
    /// default object for it: a protobuf-py message field, or a oneof
    /// member the oneof does not select.
    fn value(
        &self,
        slot: usize,
        field: &FieldInfo,
    ) -> Result<Option<&Bound<'a, PyAny>>, ReadError> {
        let cell = &self.slots[slot];
        if let Some(value) = cell.get() {
            return Ok(value.as_ref());
        }
        let fetched = self.fetch(field)?;
        Ok(cell.get_or_init(|| fetched).as_ref())
    }

    /// Reads the field off the Python object. Out of line, so that
    /// [`value`](Self::value), which runs per field, stays small enough to
    /// inline into the walk.
    #[inline(never)]
    fn fetch(&self, field: &FieldInfo) -> Result<Option<Bound<'a, PyAny>>, ReadError> {
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

    fn has_field(&self, field: &FieldInfo) -> Result<bool, ReadError> {
        let constants = self.ctx.constants;
        Ok(self
            .object
            .call_method1(&constants.has_field, (&field.attr,))?
            .extract()?)
    }

    fn tracked(&self, field: &FieldInfo) -> Result<bool, ReadError> {
        Ok(self
            .object
            .getattr(&self.ctx.constants.present)?
            .contains(field.number)?)
    }

    /// Whether a field that tracks presence is set, the way its runtime
    /// tracks it.
    fn is_set(&self, field: &Field, slot: usize, stored: &FieldInfo) -> Result<bool, ReadError> {
        match self.ctx.runtime {
            // google.protobuf tracks it: `HasField`.
            ProtoRuntime::Google => self.has_field(stored),
            // protobuf-py: a oneof member is set when the oneof selects it,
            // a message field when it is not `None`, and any other field
            // when it is in the message's `_present` set.
            ProtoRuntime::ProtobufPy if stored.oneof.is_some() => {
                Ok(self.value(slot, stored)?.is_some())
            }
            ProtoRuntime::ProtobufPy => match field.kind() {
                Kind::Singular(Singular::Message) => Ok(self.value(slot, stored)?.is_some()),
                _ => self.tracked(stored),
            },
        }
    }

    fn read(&self, field: &Field) -> Result<Option<Val<'_, PyRuntime>>, ReadError> {
        let Some(info) = &self.info else {
            // Nothing is set: every field reads as its default.
            return Ok(Some(convert(self.ctx, field.kind(), None)?));
        };
        let Some((slot, stored)) = info.find(field.number()) else {
            return Ok(None);
        };
        Ok(Some(convert(
            self.ctx,
            field.kind(),
            self.value(slot, stored)?,
        )?))
    }
}

impl Message<PyRuntime> for MessageView<'_> {
    fn encode(&self) -> Result<Vec<u8>, ReadError> {
        // An unset protobuf-py message field is `None`, and reads as a
        // message with nothing set, which encodes to nothing.
        if self.object.is_none() {
            return Ok(Vec::new());
        }
        self.ctx.serialize(&self.object)
    }

    fn has(&self, field: &Field) -> Result<bool, ReadError> {
        let Some(info) = &self.info else {
            return Ok(false);
        };
        let Some((slot, stored)) = info.find(field.number()) else {
            return Ok(false);
        };
        self.is_set(field, slot, stored)
    }

    #[inline(always)]
    fn get(&self, field: &Field) -> Result<Option<Val<'_, PyRuntime>>, ReadError> {
        self.read(field)
    }
}

/// A field's value as the validator sees it; the default when `value` is
/// `None`.
#[inline(always)]
fn convert<'a>(
    ctx: &'a Ctx<'a>,
    kind: Kind,
    value: Option<&'a Bound<'a, PyAny>>,
) -> Result<Val<'a, PyRuntime>, ReadError> {
    Ok(match kind {
        Kind::Singular(kind) => singular(ctx, kind, value)?,
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
    })
}

#[inline(always)]
fn singular<'a>(
    ctx: &'a Ctx<'a>,
    kind: Singular,
    value: Option<&'a Bound<'a, PyAny>>,
) -> Result<Val<'a, PyRuntime>, ReadError> {
    Ok(match kind {
        Singular::Message => Val::Message(MessageView::new(
            ctx,
            value
                .cloned()
                .unwrap_or_else(|| ctx.py.None().into_bound(ctx.py)),
        )?),
        Singular::Enum => Val::Enum(match value {
            Some(value) => value.extract()?,
            None => 0,
        }),
        Singular::Scalar(scalar) => match value {
            Some(value) => scalar_value(scalar, value)?,
            None => default(scalar),
        },
    })
}

#[inline(always)]
fn scalar_value<'a>(
    scalar: Scalar,
    value: &'a Bound<'a, PyAny>,
) -> Result<Val<'a, PyRuntime>, ReadError> {
    Ok(match scalar {
        Scalar::Bool => Val::Bool(value.extract()?),
        Scalar::Int32
        | Scalar::Int64
        | Scalar::Sint32
        | Scalar::Sint64
        | Scalar::Sfixed32
        | Scalar::Sfixed64 => Val::Int(value.extract()?),
        Scalar::Uint32 | Scalar::Uint64 | Scalar::Fixed32 | Scalar::Fixed64 => {
            Val::Uint(value.extract()?)
        }
        Scalar::Float | Scalar::Double => Val::Double(value.extract()?),
        Scalar::String => Val::String(
            value
                .cast::<PyString>()
                .map_err(PyErr::from)?
                .to_str()?
                .into(),
        ),
        Scalar::Bytes => Val::Bytes(
            value
                .cast::<PyBytes>()
                .map_err(PyErr::from)?
                .as_bytes()
                .into(),
        ),
    })
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

fn key<'a>(scalar: Scalar, value: &'a Bound<'a, PyAny>) -> Result<Key<'a>, ReadError> {
    Ok(match scalar_value(scalar, value)? {
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
    })
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
    fn items(&self) -> Result<&[Bound<'a, PyAny>], ReadError> {
        if let Some(items) = self.items.get() {
            return Ok(items);
        }
        let items = self.fetch_items()?;
        Ok(self.items.get_or_init(|| items))
    }

    /// Reads the elements off the Python object. Out of line, so that
    /// [`get`](List::get), which runs per element, stays small enough to
    /// inline into the walk.
    #[inline(never)]
    fn fetch_items(&self) -> Result<Vec<Bound<'a, PyAny>>, ReadError> {
        let Some(object) = self.object else {
            return Ok(Vec::new());
        };
        Ok(match object.cast::<PyList>() {
            Ok(list) => list.iter().collect(),
            Err(_) => object.try_iter()?.collect::<PyResult<Vec<_>>>()?,
        })
    }
}

impl List<PyRuntime> for ListView<'_> {
    fn len(&self) -> Result<usize, ReadError> {
        Ok(match self.items.get() {
            Some(items) => items.len(),
            None => match self.object {
                Some(object) => object.len()?,
                None => 0,
            },
        })
    }

    #[inline(always)]
    fn get(&self, index: usize) -> Result<Option<Val<'_, PyRuntime>>, ReadError> {
        match self.items()?.get(index) {
            Some(item) => Ok(Some(singular(self.ctx, self.element, Some(item))?)),
            None => Ok(None),
        }
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
    fn len(&self) -> Result<usize, ReadError> {
        Ok(match self.object {
            Some(object) => object.len()?,
            None => 0,
        })
    }

    fn for_each(
        &self,
        f: &mut dyn FnMut(Key<'_>, Val<'_, PyRuntime>) -> ControlFlow<()>,
    ) -> Result<(), ReadError> {
        let Some(object) = self.object else {
            return Ok(());
        };
        if let Ok(dict) = object.cast::<PyDict>() {
            for (k, v) in dict.iter() {
                if f(
                    key(self.key, &k)?,
                    singular(self.ctx, self.element, Some(&v))?,
                )
                .is_break()
                {
                    break;
                }
            }
            return Ok(());
        }
        let entries = object.call_method0(&self.ctx.constants.items)?.try_iter()?;
        for entry in entries {
            let (k, v) = entry?.extract::<(Bound<'_, PyAny>, Bound<'_, PyAny>)>()?;
            if f(
                key(self.key, &k)?,
                singular(self.ctx, self.element, Some(&v))?,
            )
            .is_break()
            {
                break;
            }
        }
        Ok(())
    }
}
