// Copyright 2023-2026 Buf Technologies, Inc.
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

#include "buf/validate/internal/extra_func.h"

#include "eval/public/cel_function_adapter.h"
#include "eval/public/cel_value.h"
#include "eval/public/containers/field_access.h"
#include "eval/public/containers/field_backed_list_impl.h"
#include "google/protobuf/arena.h"

namespace buf::validate::internal {

namespace cel = google::api::expr::runtime;

// This CEL function is strictly for working with protobuf-cpp, so we implement it in C++ here.
// All other custom functions are implemented in Rust.
cel::CelValue getField(
    google::protobuf::Arena* arena, cel::CelValue msgval, cel::CelValue nameval) {
  if (!msgval.IsMessage()) {
    auto* error = google::protobuf::Arena::Create<cel::CelError>(
        arena, absl::StatusCode::kInvalidArgument, "expected a message value for first argument");
    return cel::CelValue::CreateError(error);
  }
  if (!nameval.IsString()) {
    auto* error = google::protobuf::Arena::Create<cel::CelError>(
        arena, absl::StatusCode::kInvalidArgument, "expected a string value for second argument");
    return cel::CelValue::CreateError(error);
  }
  const auto* message = msgval.MessageOrDie();
  auto name = nameval.StringOrDie();
  const auto* field = message->GetDescriptor()->FindFieldByName(name.value());
  if (field == nullptr) {
    auto* error = google::protobuf::Arena::Create<cel::CelError>(
        arena, absl::StatusCode::kInvalidArgument, "no such field");
    return cel::CelValue::CreateError(error);
  }
  if (field->is_repeated()) {
    return cel::CelValue::CreateList(
        google::protobuf::Arena::Create<cel::FieldBackedListImpl>(
            arena, message, field, arena));
  } else {
    if (cel::CelValue result; cel::CreateValueFromSingleField(message, field, arena, &result).ok()) {
      return result;
    }
  }
  return cel::CelValue::CreateNull();
}

absl::Status RegisterExtraFuncs(
    google::api::expr::runtime::CelFunctionRegistry& registry, google::protobuf::Arena* regArena) {
  return cel::FunctionAdapter<cel::CelValue, cel::CelValue, cel::CelValue>::CreateAndRegister(
      "getField", false, &getField, &registry);
}
} // namespace buf::validate::internal
