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

//! The CEL backend over cel-cpp: `protovalidate-deps`' engine, with
//! protovalidate's function library registered.

pub(crate) use protovalidate_deps::Engine as Env;
use protovalidate_deps::Error;

use super::library;

/// A CEL environment knowing protovalidate's functions.
///
/// # Errors
///
/// Fails if the runtime cannot be initialized or the library cannot be
/// registered, which indicates a broken build rather than bad input.
pub(crate) fn new_env() -> Result<Env, Error> {
    let mut engine = Env::new()?;
    for function in library::FUNCTIONS {
        engine.register(
            function.name,
            function.receiver,
            function.args,
            function.call,
        )?;
    }
    Ok(engine)
}
