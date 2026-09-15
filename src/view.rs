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
//! validated in place.

use std::cell::OnceCell;
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::{Arc, RwLock};

use protovalidate::protobuf::{Field, Kind, List, Map, Message, Runtime, Scalar, Singular, Val};
use protovalidate::{Error, Validator};
use pyo3::prelude::*;
use pyo3::sync::RwLockExt;
use pyo3::types::{PyBytes, PyString, PyType};

use crate::constants::Constants;
use crate::runtime::{FieldInfo, ProtoRuntime};

/// The Python error a read raised.
type ReadError = Box<PyErr>;

/// The Python runtimes, as the validator reads them.
pub(crate) struct PyRuntime;

impl Runtime for PyRuntime {
    type Error = ReadError;
    type Message<'a> = MessageView<'a>;
    type List<'a> = ListView<'a>;
    type Map<'a> = MapView<'a>;
}

/// Where a message class keeps its fields, built once per class.
pub(crate) struct TypeInfo {
    /// Sorted by field number.
    fields: Vec<FieldInfo>,
}

impl TypeInfo {
    fn build(ctx: &Ctx<'_>, class: &Bound<'_, PyType>) -> PyResult<Self> {
        let mut fields = ctx.runtime.fields(ctx.py, class, ctx.constants)?;
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
/// is not reused.
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

    /// Validates `message`, of type `type_name`, in place. A Python error
    /// raised while reading the message comes back as [`Error::Read`].
    pub(crate) fn validate(
        &self,
        validator: &Validator,
        type_name: &str,
        message: &Bound<'py, PyAny>,
        fail_fast: bool,
    ) -> Result<(), Error<ReadError>> {
        let root = MessageView::new(self, message.clone())
            .map_err(|error| Error::Read(Box::new(error)))?;
        validator.validate_message::<PyRuntime>(type_name, &root, fail_fast)
    }

    /// The type information of `object`'s class, built on first use.
    fn type_info(&self, object: &Bound<'py, PyAny>) -> PyResult<Arc<TypeInfo>> {
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
    fn new(ctx: &'a Ctx<'a>, object: Bound<'a, PyAny>) -> PyResult<Self> {
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
    /// default object for it.
    fn value(&self, slot: usize, field: &FieldInfo) -> PyResult<Option<&Bound<'a, PyAny>>> {
        let cell = &self.slots[slot];
        if cell.get().is_none() {
            let fetched = field.fetch(&self.object, self.ctx.constants)?;
            let _ = cell.set(fetched);
        }
        Ok(cell.get().and_then(Option::as_ref))
    }
}

impl Message<PyRuntime> for MessageView<'_> {
    #[inline]
    fn encode(&self) -> Result<Vec<u8>, ReadError> {
        // An unset protobuf-py message field is `None`, and reads as a
        // message with nothing set, which encodes to nothing.
        if self.object.is_none() {
            return Ok(Vec::new());
        }
        let bytes = self
            .ctx
            .runtime
            .serialize(&self.object, self.ctx.constants)?;
        Ok(bytes.as_bytes().to_vec())
    }

    #[inline]
    fn has(&self, field: &Field) -> Result<bool, ReadError> {
        let Some(info) = &self.info else {
            return Ok(false);
        };
        let Some((slot, stored)) = info.find(field.number()) else {
            return Ok(false);
        };
        Ok(self.ctx.runtime.is_set(
            &self.object,
            stored,
            field.kind(),
            || Ok(self.value(slot, stored)?.is_some()),
            self.ctx.constants,
        )?)
    }

    #[inline]
    fn get(&self, field: &Field) -> Result<Option<Val<'_, PyRuntime>>, ReadError> {
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

/// A field's value as the validator sees it; the default when `value` is
/// `None`.
fn convert<'a>(
    ctx: &'a Ctx<'a>,
    kind: Kind,
    value: Option<&'a Bound<'a, PyAny>>,
) -> PyResult<Val<'a, PyRuntime>> {
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

fn singular<'a>(
    ctx: &'a Ctx<'a>,
    kind: Singular,
    value: Option<&'a Bound<'a, PyAny>>,
) -> PyResult<Val<'a, PyRuntime>> {
    Ok(match kind {
        Singular::Message => Val::Message(MessageView::new(
            ctx,
            value
                .cloned()
                .unwrap_or_else(|| ctx.py.None().into_bound(ctx.py)),
        )?),
        Singular::Enum => Val::Enum(match value {
            Some(value) => value.extract::<i32>()?,
            None => 0,
        }),
        Singular::Scalar(scalar) => match value {
            Some(value) => scalar_value(scalar, value)?,
            None => default(scalar),
        },
    })
}

fn scalar_value<'a>(scalar: Scalar, value: &'a Bound<'a, PyAny>) -> PyResult<Val<'a, PyRuntime>> {
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
        Scalar::String => Val::String(value.cast::<PyString>()?.to_str()?.into()),
        Scalar::Bytes => Val::Bytes(value.cast::<PyBytes>()?.as_bytes().into()),
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

/// A repeated field.
pub(crate) struct ListView<'a> {
    ctx: &'a Ctx<'a>,
    element: Singular,
    /// `None` for an unset field, which is empty.
    object: Option<&'a Bound<'a, PyAny>>,
    /// The elements, fetched all at once on first access and held here for
    /// values to borrow from.
    items: OnceCell<Vec<Bound<'a, PyAny>>>,
}

impl<'a> ListView<'a> {
    fn items(&self) -> PyResult<&[Bound<'a, PyAny>]> {
        if let Some(items) = self.items.get() {
            return Ok(items);
        }
        let items = match self.object {
            None => Vec::new(),
            Some(object) => self.ctx.runtime.list_items(object)?,
        };
        Ok(self.items.get_or_init(|| items))
    }
}

impl List<PyRuntime> for ListView<'_> {
    #[inline]
    fn len(&self) -> Result<usize, ReadError> {
        Ok(match (self.items.get(), self.object) {
            (Some(items), _) => items.len(),
            (None, Some(object)) => object.len()?,
            (None, None) => 0,
        })
    }

    #[inline]
    fn get(&self, index: usize) -> Result<Option<Val<'_, PyRuntime>>, ReadError> {
        let Some(item) = self.items()?.get(index) else {
            return Ok(None);
        };
        Ok(Some(singular(self.ctx, self.element, Some(item))?))
    }
}

/// A map field.
pub(crate) struct MapView<'a> {
    ctx: &'a Ctx<'a>,
    key: Scalar,
    element: Singular,
    /// `None` for an unset field, which is empty.
    object: Option<&'a Bound<'a, PyAny>>,
}

impl Map<PyRuntime> for MapView<'_> {
    #[inline]
    fn len(&self) -> Result<usize, ReadError> {
        Ok(match self.object {
            Some(object) => object.len()?,
            None => 0,
        })
    }

    #[inline]
    fn for_each<F>(&self, mut f: F) -> Result<(), ReadError>
    where
        F: FnMut(Val<'_, PyRuntime>, Val<'_, PyRuntime>) -> ControlFlow<()>,
    {
        let Some(object) = self.object else {
            return Ok(());
        };
        for entry in self.ctx.runtime.map_entries(object, self.ctx.constants)? {
            let (k, v) = entry?;
            let flow = f(
                scalar_value(self.key, &k)?,
                singular(self.ctx, self.element, Some(&v))?,
            );
            if flow.is_break() {
                return Ok(());
            }
        }
        Ok(())
    }
}
