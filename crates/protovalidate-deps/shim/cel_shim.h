// Copyright 2026 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// C ABI over cel-cpp with the standard functions, the string extensions, and
// the functions the Rust side registers (isEmail, isIp, unique, ...). The
// protovalidate logic itself -- walking messages, deciding which rules apply,
// building violations -- lives on the Rust side; this shim only compiles CEL
// expressions and evaluates them against values the Rust side describes.
//
// Nothing but bytes and primitives crosses this boundary. Descriptors arrive
// as serialized google.protobuf.FileDescriptorProto, messages as serialized
// payloads parsed here into a pool the Rust side keeps in sync with its own.

#ifndef PROTOVALIDATE_SHIM_CEL_SHIM_H_
#define PROTOVALIDATE_SHIM_CEL_SHIM_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// A descriptor pool, message factory, and CEL expression builder. Not thread-safe
// for concurrent compile along with evaluation.
typedef struct cel_engine cel_engine;

// A set of compiled CEL expressions sharing one `rules` message. Immutable and
// thread-safe once built.
typedef struct cel_program cel_program;

// A parsed message, owning the arena it and its sub-messages live in.
typedef struct cel_frame cel_frame;

// A message inside a frame: the frame's root or one of its sub-messages.
// Valid only while the owning frame is alive.
typedef struct cel_message cel_message;

// Status codes returned by the fallible entry points.
enum {
  CEL_OK = 0,
  CEL_ERR_COMPILATION = 1,  // an expression could not be compiled
  CEL_ERR_RUNTIME = 2,      // an expression failed while being evaluated
  CEL_ERR_ARGUMENT = 3,     // bad descriptor / unknown type / unparsable payload
  CEL_ERR_UNEXPECTED = 4,   // anything else
};

// The kind of a cel_value.
enum {
  CEL_VALUE_NULL = 0,
  CEL_VALUE_BOOL = 1,
  CEL_VALUE_INT = 2,     // int32/int64/sint*/sfixed*/enum
  CEL_VALUE_UINT = 3,    // uint32/uint64/fixed*
  CEL_VALUE_DOUBLE = 4,  // float/double
  CEL_VALUE_STRING = 5,
  CEL_VALUE_BYTES = 6,
  CEL_VALUE_LIST = 7,  // only as an argument of a registered function
};

typedef struct cel_list cel_list;

// A value. `data`/`len` are only read for strings and bytes, `list` only for
// lists; all are borrowed for the duration of the call they are passed to.
typedef struct cel_value {
  int32_t kind;
  int32_t bool_value;
  int64_t int_value;
  uint64_t uint_value;
  double double_value;
  const uint8_t* data;
  size_t len;
  const cel_list* list;
} cel_value;

// One expression to compile. Strings are borrowed for the duration of the
// call. `rule_field_number` names the field of the rules message that the
// `rule` variable is bound to while this expression runs, or 0 for none.
typedef struct cel_rule {
  const char* expression;
  size_t expression_len;
  int32_t rule_field_number;
} cel_rule;

// What the `this` variable is bound to during evaluation.
enum {
  CEL_THIS_SCALAR = 0,   // `scalar`
  CEL_THIS_MESSAGE = 1,  // `message` itself
  CEL_THIS_FIELD = 2,    // field `field_number` of `message`: a list, a map, or
                        // a singular value, by the field's descriptor
};

// One failed expression: `index` into the compiled rules, and the message the
// expression produced when it evaluated to a string (NULL when it evaluated
// to false).
typedef struct cel_failure {
  size_t index;
  char* message;
  size_t message_len;
} cel_failure;

// Creates an engine over a descriptor pool layered on the descriptors linked
// into this library (the well-known types).
//
// On failure returns NULL and, if `error` is non-NULL, stores a malloc'd
// message in *error which the caller must release with cel_free.
cel_engine* cel_engine_new(char** error);

void cel_engine_free(cel_engine* engine);

// A function implemented by the caller. `args` are the call's arguments, of
// the kinds the function was registered with. On success returns CEL_OK with
// the result in *out (a scalar; strings and bytes are copied). Otherwise
// returns another code with a message from cel_string_new in *error, which
// the expression sees as an error value.
typedef int (*cel_native_fn)(void* ctx, const cel_value* args, size_t len,
                             cel_value* out, char** error);

// Registers `fn` as CEL function `name`, callable on arguments of the given
// kinds (CEL_VALUE_*, one per argument); `receiver_style` makes the first
// argument the receiver, as in `this.isEmail()`. The same name may be
// registered with several kind lists, which CEL resolves by argument type.
// Register before compiling anything. Returns CEL_ERR_ARGUMENT for an
// unusable kind or a duplicate registration.
int cel_engine_register(cel_engine* engine, const char* name, size_t name_len,
                        int receiver_style, const int32_t* arg_kinds,
                        size_t arity, cel_native_fn fn, void* ctx,
                        char** error);

// A list passed to a registered function, valid for that call.
size_t cel_list_len(const cel_list* list);

// Reads element `index` into *out. Elements that are not scalars or lists
// read as CEL_VALUE_NULL. Returns CEL_ERR_ARGUMENT past the end.
int cel_list_get(const cel_list* list, size_t index, cel_value* out,
                 char** error);

// Allocates a string the shim releases: for a registered function's error.
char* cel_string_new(const char* data, size_t len);

// Adds one serialized FileDescriptorProto to the engine's pool. Adding a file
// whose name is already known is a no-op success. A file's imports must be
// added before the file itself.
int cel_engine_add_file(cel_engine* engine, const uint8_t* file_descriptor_proto,
                       size_t len, char** error);

// Adds every file in one serialized FileDescriptorSet, in order, with the
// same semantics as cel_engine_add_file.
int cel_engine_add_file_set(cel_engine* engine,
                           const uint8_t* file_descriptor_set, size_t len,
                           char** error);

// Compiles `rules` expressions that share one `rules` message: a serialized
// message of the type named by `rules_type_name`, or none when
// `rules_type_name_len` is 0, in which case `rules` is bound to null.
//
// On CEL_OK stores the program in *out. On failure returns CEL_ERR_COMPILATION
// (or CEL_ERR_ARGUMENT for an unknown rules type or unparsable rules) and
// stores a malloc'd message in *error.
int cel_program_new(cel_engine* engine, const char* rules_type_name,
                   size_t rules_type_name_len, const uint8_t* rules,
                   size_t rules_len, const cel_rule* exprs, size_t exprs_len,
                   cel_program** out, char** error);

void cel_program_free(cel_program* program);

// Parses `payload` as the message type named by `type_name`.
//
// On CEL_OK stores the frame in *out. On failure returns CEL_ERR_ARGUMENT and
// stores a malloc'd message in *error.
int cel_frame_new(cel_engine* engine, const char* type_name,
                 size_t type_name_len, const uint8_t* payload,
                 size_t payload_len, cel_frame** out, char** error);

void cel_frame_free(cel_frame* frame);

// The frame's root message.
const cel_message* cel_frame_message(const cel_frame* frame);

// Sub-message access. Each stores the sub-message in *out on CEL_OK, and
// returns CEL_ERR_ARGUMENT with a malloc'd message in *error when the field is
// not a message field of the expected shape or the index/key is not present.
// The results live as long as the owning frame and need no release.
int cel_message_field(const cel_message* message, int32_t field_number,
                     const cel_message** out, char** error);
int cel_message_repeated(const cel_message* message, int32_t field_number,
                        size_t index, const cel_message** out, char** error);
int cel_message_map_value(const cel_message* message, int32_t field_number,
                         const cel_value* key, const cel_message** out,
                         char** error);

// Evaluates every expression of `program` against `this`, described by
// `this_kind` and, depending on it, `scalar`, `message`, and `field_number`.
//
// On CEL_OK stores a malloc'd array of the failed expressions in *out and its
// length in *out_len (NULL and 0 when everything passed); release it with
// cel_failures_free. With `fail_fast`, evaluation stops after the first
// failure. On failure returns CEL_ERR_RUNTIME (an expression produced an error
// or a value that is neither bool nor string) or CEL_ERR_ARGUMENT (a field
// that does not exist) and stores a malloc'd message in *error.
int cel_program_eval(const cel_program* program, int this_kind,
                    const cel_value* scalar, const cel_message* message,
                    int32_t field_number, int fail_fast, cel_failure** out,
                    size_t* out_len, char** error);

void cel_failures_free(cel_failure* failures, size_t len);

// Releases an error string.
void cel_free(void* ptr);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // PROTOVALIDATE_SHIM_CEL_SHIM_H_
