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

//! What the validator tells a runtime about a oneof it asks about.

use std::borrow::Cow;
use std::fmt;

use super::{Field, Message, Runtime};

/// A oneof declared in the message being validated, as the validator
/// describes it when asking a [`Message`] which of its members is set.
///
/// Synthetic oneofs, which hold proto3 `optional` fields, are never
/// described: such a field [tracks presence](Field::has_presence) instead.
pub struct Oneof<R: Runtime> {
    name: Cow<'static, str>,
    index: u32,
    members: Vec<Field<R>>,
}

impl<R: Runtime> Clone for Oneof<R> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            index: self.index,
            members: self.members.clone(),
        }
    }
}

impl<R: Runtime> fmt::Debug for Oneof<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Oneof")
            .field("name", &self.name)
            .field("index", &self.index)
            .field("members", &self.members)
            .finish()
    }
}

impl<R: Runtime> Oneof<R> {
    pub(crate) fn new(name: String, index: u32, members: Vec<Field<R>>) -> Self {
        Self {
            name: Cow::Owned(name),
            index,
            members,
        }
    }

    /// The oneof's name in the `.proto` source.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The oneof's position among the message's oneofs, as declared in its
    /// `DescriptorProto.oneof_decl`, synthetic oneofs included.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The oneof's fields, in declaration order.
    #[must_use]
    pub fn members(&self) -> &[Field<R>] {
        &self.members
    }
}

/// Which member of `oneof` is set, by asking [`Message::has`] of each in
/// turn: the default of [`Message::which_oneof`], for a runtime that does
/// not track it, or cannot for a particular message.
///
/// # Errors
///
/// The runtime could not tell whether a member is set.
pub fn which_oneof_by_has<R: Runtime>(
    message: &(impl Message<R> + ?Sized),
    oneof: &Oneof<R>,
) -> Result<Option<u32>, R::Error> {
    for member in oneof.members() {
        if message.has(member)? {
            return Ok(Some(member.number()));
        }
    }
    Ok(None)
}
