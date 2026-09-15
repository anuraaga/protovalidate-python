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

//! The CEL backend, behind the `cel` feature.
//!
//! Everything the validator needs from a CEL runtime passes through the
//! types re-exported here: an [`Env`] that compiles rule expressions into a
//! [`Program`], and a [`Frame`] holding a message that programs can be
//! evaluated against. They are `protovalidate-deps`' engine over cel-cpp,
//! with protovalidate's function library ([`library`]) registered by
//! [`new_env`]. Without the feature this module does not exist, and the
//! rules builder reports a custom CEL rule as a compilation error.

mod cpp;
mod library;

pub(crate) use cpp::{Env, new_env};
pub(crate) use protovalidate_deps::{Error, Expression, Frame, MessageRef, Program, Scalar, This};
