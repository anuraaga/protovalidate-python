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

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard};

use buffa::Message as _;
use buffa_descriptor::MessageIndex;
use buffa_descriptor::generated::descriptor::FileDescriptorSet;

#[cfg(feature = "cel")]
use crate::cel;
use crate::descriptors::{self, Descriptors};
use crate::error::Internal;
use crate::protobuf::{Payload, Runtime};
use crate::rules::MessageEvaluator;
use crate::rules::build::Builder;
use crate::rules::eval::Walker;
use crate::validate::{Violation as ViolationPb, Violations};
use crate::{DescriptorError, Error, ValidationError};

/// The compiled rules of every message type validated so far.
type Cache = HashMap<MessageIndex, Arc<MessageEvaluator>>;

/// The violations as a serialized `buf.validate.Violations`.
fn encode_violations(violations: Vec<ViolationPb>) -> Vec<u8> {
    Violations {
        violations,
        ..Default::default()
    }
    .encode_to_vec()
}

/// A CEL environment knowing the `buf.validate` schema.
#[cfg(feature = "cel")]
fn cel_env() -> cel::Env {
    let mut env = cel::new_env()
        .unwrap_or_else(|error| panic!("could not initialize the CEL runtime: {error}"));
    let set = descriptors::decode_file_set(descriptors::BASE_DESCRIPTOR_SET)
        .expect("embedded descriptor set decodes");
    for file in &set.file {
        env.add_file(&file.encode_to_vec())
            .unwrap_or_else(|error| panic!("could not register the buf.validate schema: {error}"));
    }
    env
}

/// Validates Protobuf messages against the rules in their descriptors.
///
/// Descriptors are registered serialized, and a message is read in place
/// through a [`Runtime`] the caller implements over its own Protobuf
/// runtime.
pub struct Validator {
    descriptors: Descriptors,
    #[cfg(feature = "cel")]
    env: RwLock<cel::Env>,
    cache: RwLock<Cache>,
}

impl fmt::Debug for Validator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Validator").finish_non_exhaustive()
    }
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator {
    /// Creates a validator.
    ///
    /// Use `add_*` methods to register file descriptors for the messages you will validate.
    #[must_use]
    pub fn new() -> Self {
        Self {
            descriptors: Descriptors::new(),
            #[cfg(feature = "cel")]
            env: RwLock::new(cel_env()),
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a serialized `google.protobuf.FileDescriptorProto`.
    ///
    /// A file's imports must be registered before the file itself. Adding a
    /// file whose name is already known is a no-op, so descriptors
    /// may be re-added freely.
    ///
    /// # Errors
    ///
    /// Fails if the bytes do not parse, the file is invalid, or one of its
    /// imports has not been registered.
    pub fn add_file_descriptor_bytes(&mut self, file: &[u8]) -> Result<(), DescriptorError> {
        let proto = descriptors::decode_file(file).map_err(DescriptorError::new)?;
        let set = FileDescriptorSet {
            file: vec![proto],
            ..Default::default()
        };
        self.descriptors
            .add_file_set(set)
            .map_err(DescriptorError::new)?;
        #[cfg(feature = "cel")]
        self.env
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .add_file(file)
            .map_err(|error| DescriptorError::new(error.to_string()))?;
        Ok(())
    }

    /// Validates a message read in place through a [`Runtime`].
    ///
    /// `type_name` is the fully-qualified message type, without a leading
    /// dot; its descriptor must already be registered. `payload` is the
    /// message's serialized form, produced only if a CEL rule binds the
    /// message itself, a repeated field or a map to `this`. With `fail_fast`
    /// validation stops at the first violation, rather than accumulating
    /// them all.
    ///
    /// # Errors
    ///
    /// A message that breaks its rules returns [`Error::Validation`],
    /// carrying the violations as a serialized `buf.validate.Violations`.
    /// The other variants mean validation itself failed: an unknown type or
    /// unparsable payload ([`Error::Argument`]), rules that do not compile
    /// ([`Error::Compilation`]), or a rule failing to evaluate
    /// ([`Error::Evaluation`]).
    pub fn validate_message<R: Runtime>(
        &self,
        type_name: &str,
        message: &R::Message<'_>,
        payload: Payload<'_>,
        fail_fast: bool,
    ) -> Result<(), Error> {
        let violations = self.run::<R>(type_name, message, payload, fail_fast)?;
        if violations.is_empty() {
            return Ok(());
        }
        Err(Error::Validation(ValidationError::new(encode_violations(
            violations,
        ))))
    }

    fn run<R: Runtime>(
        &self,
        type_name: &str,
        message: &R::Message<'_>,
        payload: Payload<'_>,
        fail_fast: bool,
    ) -> Result<Vec<ViolationPb>, Internal> {
        let index = self.message_index(type_name)?;
        let evaluators = self.evaluators(index)?;
        #[cfg(feature = "cel")]
        let env = self.env.read().unwrap_or_else(PoisonError::into_inner);
        #[cfg(feature = "cel")]
        let walker = Walker::<R>::new(&self.descriptors, &env, &evaluators, fail_fast);
        #[cfg(not(feature = "cel"))]
        let walker = Walker::<R>::new(&self.descriptors, &evaluators, fail_fast);
        Ok(walker.validate(message, type_name, payload, &evaluators[&index])?)
    }

    fn message_index(&self, type_name: &str) -> Result<MessageIndex, Internal> {
        self.descriptors
            .pool
            .message_index(type_name)
            .ok_or_else(|| Internal::Argument(format!("unknown message type: {type_name}")))
    }

    /// The cache, with the rules of `index` and every type reachable from
    /// it compiled.
    ///
    /// Rules compile lazily, on the first validation of a type, the whole
    /// reachable closure at once. Failures are not cached and are reported
    /// again on every call.
    fn evaluators(&self, index: MessageIndex) -> Result<RwLockReadGuard<'_, Cache>, Internal> {
        let cache = self.read_cache();
        if cache.contains_key(&index) {
            return Ok(cache);
        }
        let mut built = HashMap::new();
        #[cfg(feature = "cel")]
        {
            let mut env = self.env.write().unwrap_or_else(PoisonError::into_inner);
            let mut builder = Builder::new(&self.descriptors, &mut env);
            builder.build_closure(index, &cache, &mut built)?;
        }
        #[cfg(not(feature = "cel"))]
        {
            let mut builder = Builder::new(&self.descriptors);
            builder.build_closure(index, &cache, &mut built)?;
        }
        drop(cache);
        self.cache
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(built);
        Ok(self.read_cache())
    }

    fn read_cache(&self) -> RwLockReadGuard<'_, Cache> {
        self.cache.read().unwrap_or_else(PoisonError::into_inner)
    }
}
