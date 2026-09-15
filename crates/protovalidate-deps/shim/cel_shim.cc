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

#include "cel_shim.h"

#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/types/optional.h"
#include "buf/validate/internal/extra_func.h"
#include "eval/public/activation.h"
#include "eval/public/builtin_func_registrar.h"
#include "eval/public/cel_expr_builder_factory.h"
#include "eval/public/cel_expression.h"
#include "eval/public/cel_function.h"
#include "eval/public/cel_function_registry.h"
#include "eval/public/cel_options.h"
#include "eval/public/cel_value.h"
#include "eval/public/containers/field_access.h"
#include "eval/public/containers/field_backed_list_impl.h"
#include "eval/public/containers/field_backed_map_impl.h"
#include "eval/public/string_extension_func_registrar.h"
#include "eval/public/structs/cel_proto_wrapper.h"
#include "google/protobuf/arena.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/descriptor.pb.h"
#include "google/protobuf/dynamic_message.h"
#include "google/protobuf/message.h"
#include "parser/parser.h"

namespace celrt = google::api::expr::runtime;

namespace {

// Collects BuildFile errors so they reach the caller instead of being logged.
class StringErrorCollector : public google::protobuf::DescriptorPool::ErrorCollector {
 public:
  void RecordError(absl::string_view filename, absl::string_view element_name,
                   const google::protobuf::Message* descriptor,
                   ErrorLocation location, absl::string_view message) override {
    if (!text_.empty()) text_ += "; ";
    absl::StrAppend(&text_, filename, ": ", element_name, ": ", message);
  }

  const std::string& text() const { return text_; }

 private:
  std::string text_;
};

// ParseFromArray takes an int length, so a buffer at or above 2 GiB would
// narrow to a negative one. Protobuf cannot represent a message that large
// either, so safe to reject it.
bool FitsInInt(size_t len) {
  return len <= static_cast<size_t>(std::numeric_limits<int>::max());
}

char* CopyCString(absl::string_view value) {
  char* out = static_cast<char*>(std::malloc(value.size() + 1));
  if (out == nullptr) return nullptr;
  std::memcpy(out, value.data(), value.size());
  out[value.size()] = '\0';
  return out;
}

void SetError(char** error, absl::string_view message) {
  if (error != nullptr) *error = CopyCString(message);
}

// Resolves a field of `message` by number, extensions included.
const google::protobuf::FieldDescriptor* FindField(
    const google::protobuf::Message& message, int32_t number) {
  const google::protobuf::FieldDescriptor* field =
      message.GetDescriptor()->FindFieldByNumber(number);
  if (field == nullptr) {
    field = message.GetReflection()->FindKnownExtensionByNumber(number);
  }
  return field;
}

// The CEL value of one field of a message: a list, a map, or the wrapped
// singular value; how `this` is bound for field rules and `rule` for
// predefined rules.
celrt::CelValue FieldToCelValue(const google::protobuf::Message* message,
                              const google::protobuf::FieldDescriptor* field,
                              google::protobuf::Arena* arena) {
  if (field->is_map()) {
    return celrt::CelValue::CreateMap(
        google::protobuf::Arena::Create<celrt::FieldBackedMapImpl>(
            arena, message, field, arena));
  }
  if (field->is_repeated()) {
    return celrt::CelValue::CreateList(
        google::protobuf::Arena::Create<celrt::FieldBackedListImpl>(
            arena, message, field, arena));
  }
  celrt::CelValue result;
  if (celrt::CreateValueFromSingleField(message, field, arena, &result).ok()) {
    return result;
  }
  return celrt::CelValue::CreateNull();
}

celrt::CelValue ScalarToCelValue(const cel_value& value) {
  switch (value.kind) {
    case CEL_VALUE_BOOL:
      return celrt::CelValue::CreateBool(value.bool_value != 0);
    case CEL_VALUE_INT:
      return celrt::CelValue::CreateInt64(value.int_value);
    case CEL_VALUE_UINT:
      return celrt::CelValue::CreateUint64(value.uint_value);
    case CEL_VALUE_DOUBLE:
      return celrt::CelValue::CreateDouble(value.double_value);
    case CEL_VALUE_STRING:
      return celrt::CelValue::CreateStringView(absl::string_view(
          reinterpret_cast<const char*>(value.data), value.len));
    case CEL_VALUE_BYTES:
      return celrt::CelValue::CreateBytesView(absl::string_view(
          reinterpret_cast<const char*>(value.data), value.len));
    default:
      return celrt::CelValue::CreateNull();
  }
}

struct CompiledRule {
  std::unique_ptr<celrt::CelExpression> expression;
  bool has_rule = false;
  celrt::CelValue rule;
};

// Releases the messages of failures that never reached the caller.
void FreeFailureMessages(std::vector<cel_failure>& failures) {
  for (cel_failure& failure : failures) std::free(failure.message);
  failures.clear();
}

}  // namespace

// The pool is an overlay on the descriptors compiled into this library, so
// the well-known types always match the C++ types cel-cpp was built against,
// and user files are only consulted for names the underlay does not define.
//
// Files are added with BuildFile rather than through a DescriptorDatabase,
// because the engine learns about descriptors incrementally and a
// database-backed pool must not be mutated after construction. The
// consequence for callers: a file's imports must be added before the file.
struct cel_engine {
  cel_engine()
      : pool(google::protobuf::DescriptorPool::generated_pool()),
        message_factory(&pool) {}

  google::protobuf::DescriptorPool pool;
  google::protobuf::DynamicMessageFactory message_factory;
  // The builder and the arena constant folding allocates into, both used by
  // every compilation.
  google::protobuf::Arena constant_arena;
  std::unique_ptr<celrt::CelExpressionBuilder> builder;
};

struct cel_program {
  // Owns the rules message and the containers the `rule` values view.
  google::protobuf::Arena arena;
  celrt::CelValue rules = celrt::CelValue::CreateNull();
  std::vector<CompiledRule> exprs;
};

struct cel_frame {
  google::protobuf::Arena arena;
  const google::protobuf::Message* message = nullptr;
};

namespace {

// Builds one already-parsed file into the engine's pool. Adding a file whose
// name is already known -- from the linked-in descriptors or a previous add
// -- is a no-op success.
int AddFileProto(cel_engine* engine,
                 const google::protobuf::FileDescriptorProto& proto,
                 char** error) {
  if (engine->pool.FindFileByName(proto.name()) != nullptr) return CEL_OK;

  StringErrorCollector collector;
  if (engine->pool.BuildFileCollectingErrors(proto, &collector) == nullptr) {
    std::string message =
        "could not add " + proto.name() + " to descriptor pool";
    if (!collector.text().empty()) message += ": " + collector.text();
    SetError(error, message);
    return CEL_ERR_ARGUMENT;
  }
  return CEL_OK;
}

// The expression builder, with the options and functions rules need.
absl::StatusOr<std::unique_ptr<celrt::CelExpressionBuilder>> NewBuilder(
    google::protobuf::Arena* arena) {
  celrt::InterpreterOptions options;
  options.enable_qualified_type_identifiers = true;
  options.enable_timestamp_duration_overflow_errors = true;
  options.enable_heterogeneous_equality = true;
  options.enable_empty_wrapper_null_unboxing = true;
  options.enable_regex_precompilation = true;
  options.constant_folding = true;
  options.constant_arena = arena;

  std::unique_ptr<celrt::CelExpressionBuilder> builder =
      celrt::CreateCelExpressionBuilder(options);
  absl::Status status =
      celrt::RegisterBuiltinFunctions(builder->GetRegistry(), options);
  if (!status.ok()) return status;
  status = celrt::RegisterStringExtensionFunctions(builder->GetRegistry());
  if (!status.ok()) return status;
  status = buf::validate::internal::RegisterExtraFuncs(*builder->GetRegistry(),
                                                       arena);
  if (!status.ok()) return status;
  return builder;
}

// The `cel_value` for a CEL value a registered function is called with, or
// false for a kind that has no `cel_value` form.
bool ToValue(const celrt::CelValue& value, cel_value* out) {
  *out = cel_value{};
  switch (value.type()) {
    case celrt::CelValue::Type::kBool:
      out->kind = CEL_VALUE_BOOL;
      out->bool_value = value.BoolOrDie() ? 1 : 0;
      return true;
    case celrt::CelValue::Type::kInt64:
      out->kind = CEL_VALUE_INT;
      out->int_value = value.Int64OrDie();
      return true;
    case celrt::CelValue::Type::kUint64:
      out->kind = CEL_VALUE_UINT;
      out->uint_value = value.Uint64OrDie();
      return true;
    case celrt::CelValue::Type::kDouble:
      out->kind = CEL_VALUE_DOUBLE;
      out->double_value = value.DoubleOrDie();
      return true;
    case celrt::CelValue::Type::kString: {
      absl::string_view str = value.StringOrDie().value();
      out->kind = CEL_VALUE_STRING;
      out->data = reinterpret_cast<const uint8_t*>(str.data());
      out->len = str.size();
      return true;
    }
    case celrt::CelValue::Type::kBytes: {
      absl::string_view str = value.BytesOrDie().value();
      out->kind = CEL_VALUE_BYTES;
      out->data = reinterpret_cast<const uint8_t*>(str.data());
      out->len = str.size();
      return true;
    }
    case celrt::CelValue::Type::kList:
      out->kind = CEL_VALUE_LIST;
      out->list = reinterpret_cast<const cel_list*>(value.ListOrDie());
      return true;
    default:
      return false;
  }
}

// The CEL value of a registered function's result; strings and bytes are
// copied into `arena`.
absl::StatusOr<celrt::CelValue> FromValue(const cel_value& value,
                                          google::protobuf::Arena* arena) {
  switch (value.kind) {
    case CEL_VALUE_NULL:
      return celrt::CelValue::CreateNull();
    case CEL_VALUE_BOOL:
      return celrt::CelValue::CreateBool(value.bool_value != 0);
    case CEL_VALUE_INT:
      return celrt::CelValue::CreateInt64(value.int_value);
    case CEL_VALUE_UINT:
      return celrt::CelValue::CreateUint64(value.uint_value);
    case CEL_VALUE_DOUBLE:
      return celrt::CelValue::CreateDouble(value.double_value);
    case CEL_VALUE_STRING:
      return celrt::CelValue::CreateString(google::protobuf::Arena::Create<std::string>(
          arena, reinterpret_cast<const char*>(value.data), value.len));
    case CEL_VALUE_BYTES:
      return celrt::CelValue::CreateBytes(google::protobuf::Arena::Create<std::string>(
          arena, reinterpret_cast<const char*>(value.data), value.len));
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("unsupported result kind ", value.kind));
  }
}

absl::optional<celrt::CelValue::Type> TypeOfKind(int32_t kind) {
  switch (kind) {
    case CEL_VALUE_BOOL:
      return celrt::CelValue::Type::kBool;
    case CEL_VALUE_INT:
      return celrt::CelValue::Type::kInt64;
    case CEL_VALUE_UINT:
      return celrt::CelValue::Type::kUint64;
    case CEL_VALUE_DOUBLE:
      return celrt::CelValue::Type::kDouble;
    case CEL_VALUE_STRING:
      return celrt::CelValue::Type::kString;
    case CEL_VALUE_BYTES:
      return celrt::CelValue::Type::kBytes;
    case CEL_VALUE_LIST:
      return celrt::CelValue::Type::kList;
    default:
      return absl::nullopt;
  }
}

// A CEL function implemented by the caller through `cel_native_fn`.
class NativeFunction : public celrt::CelFunction {
 public:
  NativeFunction(celrt::CelFunctionDescriptor descriptor, cel_native_fn fn,
                 void* ctx)
      : celrt::CelFunction(std::move(descriptor)), fn_(fn), ctx_(ctx) {}

  absl::Status Evaluate(absl::Span<const celrt::CelValue> arguments,
                        celrt::CelValue* result,
                        google::protobuf::Arena* arena) const override {
    std::vector<cel_value> args(arguments.size());
    for (size_t i = 0; i < arguments.size(); i++) {
      if (!ToValue(arguments[i], &args[i])) {
        *result = celrt::CelValue::CreateError(
            google::protobuf::Arena::Create<celrt::CelError>(
                arena, absl::StatusCode::kInvalidArgument,
                absl::StrCat("unsupported argument type ",
                             celrt::CelValue::TypeName(arguments[i].type()))));
        return absl::OkStatus();
      }
    }
    cel_value out{};
    char* error = nullptr;
    int code = fn_(ctx_, args.data(), args.size(), &out, &error);
    if (code != CEL_OK) {
      std::string message = error != nullptr ? error : "function failed";
      std::free(error);
      *result = celrt::CelValue::CreateError(
          google::protobuf::Arena::Create<celrt::CelError>(
              arena, absl::StatusCode::kInvalidArgument, message));
      return absl::OkStatus();
    }
    absl::StatusOr<celrt::CelValue> value = FromValue(out, arena);
    if (!value.ok()) {
      *result = celrt::CelValue::CreateError(
          google::protobuf::Arena::Create<celrt::CelError>(arena,
                                                           value.status()));
      return absl::OkStatus();
    }
    *result = *value;
    return absl::OkStatus();
  }

 private:
  cel_native_fn fn_;
  void* ctx_;
};

// Parses `payload` as `descriptor` into `arena`.
absl::StatusOr<google::protobuf::Message*> ParseMessage(
    cel_engine* engine, const google::protobuf::Descriptor* descriptor,
    const uint8_t* payload, size_t payload_len, google::protobuf::Arena* arena) {
  if (!FitsInInt(payload_len)) {
    return absl::InvalidArgumentError("payload is too large");
  }
  google::protobuf::Message* message =
      engine->message_factory.GetPrototype(descriptor)->New(arena);
  if (!message->ParseFromArray(payload, static_cast<int>(payload_len))) {
    return absl::InvalidArgumentError(
        absl::StrCat("could not parse payload as ", descriptor->full_name()));
  }
  return message;
}

// The CEL value for `this`, per the caller's description.
absl::StatusOr<celrt::CelValue> ThisValue(int this_kind, const cel_value* scalar,
                                        const google::protobuf::Message* message,
                                        int32_t field_number,
                                        google::protobuf::Arena* arena) {
  switch (this_kind) {
    case CEL_THIS_SCALAR:
      if (scalar == nullptr) {
        return absl::InvalidArgumentError("missing scalar for this");
      }
      return ScalarToCelValue(*scalar);
    case CEL_THIS_MESSAGE:
      if (message == nullptr) {
        return absl::InvalidArgumentError("missing message for this");
      }
      return celrt::CelProtoWrapper::CreateMessage(message, arena);
    case CEL_THIS_FIELD: {
      if (message == nullptr) {
        return absl::InvalidArgumentError("missing message for this");
      }
      const google::protobuf::FieldDescriptor* field =
          FindField(*message, field_number);
      if (field == nullptr) {
        return absl::InvalidArgumentError(
            absl::StrCat("no field ", field_number, " in ",
                         message->GetDescriptor()->full_name()));
      }
      return FieldToCelValue(message, field, arena);
    }
    default:
      return absl::InvalidArgumentError("unknown kind for this");
  }
}

}  // namespace

extern "C" {

cel_engine* cel_engine_new(char** error) {
  auto engine = std::make_unique<cel_engine>();
  auto builder = NewBuilder(&engine->constant_arena);
  if (!builder.ok()) {
    SetError(error, builder.status().message());
    return nullptr;
  }
  engine->builder = std::move(*builder);
  return engine.release();
}

void cel_engine_free(cel_engine* engine) { delete engine; }

int cel_engine_register(cel_engine* engine, const char* name, size_t name_len,
                        int receiver_style, const int32_t* arg_kinds,
                        size_t arity, cel_native_fn fn, void* ctx,
                        char** error) {
  if (fn == nullptr) {
    SetError(error, "function pointer must be set");
    return CEL_ERR_ARGUMENT;
  }
  std::vector<celrt::CelValue::Type> types;
  types.reserve(arity);
  for (size_t i = 0; i < arity; i++) {
    absl::optional<celrt::CelValue::Type> type = TypeOfKind(arg_kinds[i]);
    if (!type.has_value()) {
      SetError(error, absl::StrCat("unusable argument kind ", arg_kinds[i]));
      return CEL_ERR_ARGUMENT;
    }
    types.push_back(*type);
  }
  celrt::CelFunctionDescriptor descriptor(std::string(name, name_len),
                                          receiver_style != 0,
                                          std::move(types));
  absl::Status status = engine->builder->GetRegistry()->Register(
      std::make_unique<NativeFunction>(std::move(descriptor), fn, ctx));
  if (!status.ok()) {
    SetError(error, status.message());
    return CEL_ERR_ARGUMENT;
  }
  return CEL_OK;
}

size_t cel_list_len(const cel_list* list) {
  return static_cast<size_t>(
      reinterpret_cast<const celrt::CelList*>(list)->size());
}

int cel_list_get(const cel_list* list, size_t index, cel_value* out,
                 char** error) {
  const auto* cel_list = reinterpret_cast<const celrt::CelList*>(list);
  if (!FitsInInt(index) || static_cast<int>(index) >= cel_list->size()) {
    SetError(error, "list index out of range");
    return CEL_ERR_ARGUMENT;
  }
  if (!ToValue((*cel_list)[static_cast<int>(index)], out)) {
    *out = cel_value{};
    out->kind = CEL_VALUE_NULL;
  }
  return CEL_OK;
}

char* cel_string_new(const char* data, size_t len) {
  char* out = static_cast<char*>(std::malloc(len + 1));
  if (out == nullptr) return nullptr;
  std::memcpy(out, data, len);
  out[len] = '\0';
  return out;
}

int cel_engine_add_file(cel_engine* engine, const uint8_t* file_descriptor_proto,
                       size_t len, char** error) {
  if (!FitsInInt(len)) {
    SetError(error, "FileDescriptorProto is too large");
    return CEL_ERR_ARGUMENT;
  }
  google::protobuf::FileDescriptorProto proto;
  if (!proto.ParseFromArray(file_descriptor_proto, static_cast<int>(len))) {
    SetError(error, "could not parse FileDescriptorProto");
    return CEL_ERR_ARGUMENT;
  }
  return AddFileProto(engine, proto, error);
}

int cel_engine_add_file_set(cel_engine* engine,
                           const uint8_t* file_descriptor_set, size_t len,
                           char** error) {
  if (!FitsInInt(len)) {
    SetError(error, "FileDescriptorSet is too large");
    return CEL_ERR_ARGUMENT;
  }
  google::protobuf::FileDescriptorSet set;
  if (!set.ParseFromArray(file_descriptor_set, static_cast<int>(len))) {
    SetError(error, "could not parse FileDescriptorSet");
    return CEL_ERR_ARGUMENT;
  }
  for (const google::protobuf::FileDescriptorProto& proto : set.file()) {
    if (int status = AddFileProto(engine, proto, error); status != CEL_OK) {
      return status;
    }
  }
  return CEL_OK;
}

int cel_program_new(cel_engine* engine, const char* rules_type_name,
                   size_t rules_type_name_len, const uint8_t* rules,
                   size_t rules_len, const cel_rule* exprs, size_t exprs_len,
                   cel_program** out, char** error) {
  auto program = std::make_unique<cel_program>();
  const google::protobuf::Message* rules_message = nullptr;
  if (rules_type_name_len > 0) {
    absl::string_view name(rules_type_name, rules_type_name_len);
    const google::protobuf::Descriptor* descriptor =
        engine->pool.FindMessageTypeByName(name);
    if (descriptor == nullptr) {
      SetError(error, absl::StrCat("unknown rules type: ", name));
      return CEL_ERR_ARGUMENT;
    }
    auto parsed =
        ParseMessage(engine, descriptor, rules, rules_len, &program->arena);
    if (!parsed.ok()) {
      SetError(error, parsed.status().message());
      return CEL_ERR_ARGUMENT;
    }
    rules_message = *parsed;
    program->rules =
        celrt::CelProtoWrapper::CreateMessage(rules_message, &program->arena);
  }

  program->exprs.reserve(exprs_len);
  for (size_t i = 0; i < exprs_len; i++) {
    const cel_rule& rule = exprs[i];
    absl::string_view expression(rule.expression, rule.expression_len);
    auto parsed = google::api::expr::parser::Parse(expression);
    if (!parsed.ok()) {
      SetError(error, parsed.status().message());
      return CEL_ERR_COMPILATION;
    }
    auto compiled = engine->builder->CreateExpression(&parsed->expr(),
                                                      &parsed->source_info());
    if (!compiled.ok()) {
      SetError(error, compiled.status().message());
      return CEL_ERR_COMPILATION;
    }
    CompiledRule entry;
    entry.expression = std::move(*compiled);
    if (rules_message != nullptr && rule.rule_field_number != 0) {
      const google::protobuf::FieldDescriptor* field =
          FindField(*rules_message, rule.rule_field_number);
      if (field == nullptr) {
        SetError(error, absl::StrCat("no rule field ", rule.rule_field_number,
                                     " in ",
                                     rules_message->GetDescriptor()->full_name()));
        return CEL_ERR_ARGUMENT;
      }
      entry.has_rule = true;
      entry.rule = FieldToCelValue(rules_message, field, &program->arena);
    }
    program->exprs.push_back(std::move(entry));
  }
  *out = program.release();
  return CEL_OK;
}

void cel_program_free(cel_program* program) { delete program; }

int cel_frame_new(cel_engine* engine, const char* type_name,
                 size_t type_name_len, const uint8_t* payload,
                 size_t payload_len, cel_frame** out, char** error) {
  absl::string_view name(type_name, type_name_len);
  const google::protobuf::Descriptor* descriptor =
      engine->pool.FindMessageTypeByName(name);
  if (descriptor == nullptr) {
    SetError(error, absl::StrCat("unknown message type: ", name));
    return CEL_ERR_ARGUMENT;
  }
  auto frame = std::make_unique<cel_frame>();
  auto parsed =
      ParseMessage(engine, descriptor, payload, payload_len, &frame->arena);
  if (!parsed.ok()) {
    SetError(error, parsed.status().message());
    return CEL_ERR_ARGUMENT;
  }
  frame->message = *parsed;
  *out = frame.release();
  return CEL_OK;
}

void cel_frame_free(cel_frame* frame) { delete frame; }

int cel_program_eval(const cel_program* program, int this_kind,
                    const cel_value* scalar, const cel_frame* frame,
                    int32_t field_number, int fail_fast, cel_failure** out,
                    size_t* out_len, char** error) {
  *out = nullptr;
  *out_len = 0;
  google::protobuf::Arena arena;
  const google::protobuf::Message* message =
      frame != nullptr ? frame->message : nullptr;
  auto this_value = ThisValue(this_kind, scalar, message, field_number, &arena);
  if (!this_value.ok()) {
    SetError(error, this_value.status().message());
    return CEL_ERR_ARGUMENT;
  }

  celrt::Activation activation;
  activation.InsertValue("this", *this_value);
  activation.InsertValue("rules", program->rules);
  activation.InsertValue("now", celrt::CelValue::CreateTimestamp(absl::Now()));

  std::vector<cel_failure> failures;
  for (size_t i = 0; i < program->exprs.size(); i++) {
    const CompiledRule& rule = program->exprs[i];
    if (rule.has_rule) {
      activation.InsertValue("rule", rule.rule);
    }
    auto result = rule.expression->Evaluate(activation, &arena);
    activation.RemoveValueEntry("rule");
    if (!result.ok()) {
      FreeFailureMessages(failures);
      SetError(error, result.status().message());
      return CEL_ERR_RUNTIME;
    }
    const celrt::CelValue& value = *result;
    if (value.IsBool()) {
      if (value.BoolOrDie()) continue;
      failures.push_back(cel_failure{i, nullptr, 0});
    } else if (value.IsString()) {
      absl::string_view text = value.StringOrDie().value();
      if (text.empty()) continue;
      failures.push_back(cel_failure{i, CopyCString(text), text.size()});
    } else {
      FreeFailureMessages(failures);
      if (value.IsError()) {
        SetError(error, value.ErrorOrDie()->message());
      } else {
        SetError(error, "invalid result type");
      }
      return CEL_ERR_RUNTIME;
    }
    if (fail_fast != 0) break;
  }
  if (failures.empty()) return CEL_OK;

  auto* buffer =
      static_cast<cel_failure*>(std::malloc(failures.size() * sizeof(cel_failure)));
  if (buffer == nullptr) {
    FreeFailureMessages(failures);
    SetError(error, "out of memory");
    return CEL_ERR_UNEXPECTED;
  }
  std::memcpy(buffer, failures.data(), failures.size() * sizeof(cel_failure));
  *out = buffer;
  *out_len = failures.size();
  return CEL_OK;
}

void cel_failures_free(cel_failure* failures, size_t len) {
  if (failures == nullptr) return;
  for (size_t i = 0; i < len; i++) std::free(failures[i].message);
  std::free(failures);
}

void cel_free(void* ptr) { std::free(ptr); }

}  // extern "C"
