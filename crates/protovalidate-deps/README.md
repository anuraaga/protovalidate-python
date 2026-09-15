# protovalidate-deps

The compiled C++ behind the `protovalidate` crate: the [cel-cpp] evaluator, the protobuf runtime, RE2, and abseil, exposed through the C ABI shim in `shim/` and the safe Rust API over it in `src/`, which is the only place the protovalidate crates use `unsafe`. The validation logic and protovalidate's CEL functions are Rust, in `protovalidate`, which registers the functions through this crate; only `getField` is C++.

This crate exists so the expensive C++ compilation is versioned and cached independently of the `protovalidate` crate that wraps it. It is not meant to be used directly — depend on `protovalidate`.

Upstream sources are git submodules under `third_party/`, cel-cpp at the pinned ref and its dependencies at the versions bazel resolves for it; which files to compile is recorded in `filelists/`, and bazel-generated code is checked in under `gen/`. All of it is produced by `scripts/extract_native_sources.py` (`poe generate-vendored`) — see the repository's contributing guide.

[cel-cpp]: https://github.com/google/cel-cpp
