# Copyright 2023-2026 Buf Technologies, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys

# The buf.validate stubs (including the conformance harness) live in test/gen;
# put it on the path before the `buf` imports so the top-level `buf` package
# resolves there.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gen"))

import celpy
import protobuf
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf import message as google_message
from protobuf import Oneof, Registry
from protobuf import wkt as pb_wkt

import protovalidate
from buf.validate import validate_pb
from buf.validate.conformance.harness import harness_pb

# When set, test messages are parsed as google.protobuf messages so the suite
# exercises the legacy conversion path instead of protobuf-py directly.
_LEGACY = os.environ.get("PROTOVALIDATE_CONFORMANCE_LEGACY") == "1"


def build_google_pool(fdset: pb_wkt.FileDescriptorSet) -> descriptor_pool.DescriptorPool:
    """Build a google descriptor pool with the set's files, dependencies first."""
    pool = descriptor_pool.DescriptorPool()
    by_name = {file.name: file for file in fdset.file}
    added: set[str] = set()

    def add(name: str) -> None:
        proto = by_name.get(name)
        if proto is None or name in added:
            return
        added.add(name)
        for dep in proto.dependency:
            add(dep)
        pool.Add(descriptor_pb2.FileDescriptorProto.FromString(proto.to_binary()))

    for file in fdset.file:
        add(file.name)
    return pool


def run_test_case(
    validator: protovalidate.Validator, tc: protobuf.Message | google_message.Message, result: harness_pb.TestResult
) -> harness_pb.TestResult:
    # Run the validator
    try:
        violations = validator.collect_violations(tc)
        if len(violations) > 0:
            # protovalidate bundles its own relocatable validate_pb stub, a
            # distinct class identity from the harness gen here; cross by binary.
            pv_violations = protovalidate.Violations(violations=[violation.proto for violation in violations])
            result.result = Oneof(
                field="validation_error",
                value=validate_pb.Violations.from_binary(pv_violations.to_binary()),
            )
        else:
            result.result = Oneof(field="success", value=True)
    except celpy.CELEvalError as e:
        result.result = Oneof(field="runtime_error", value=str(e))
    except protovalidate.CompilationError as e:
        result.result = Oneof(field="compilation_error", value=str(e))
    except Exception as e:
        result.result = Oneof(field="unexpected_error", value=str(e))
    return result


def run_any_test_case(
    validator: protovalidate.Validator,
    registry: Registry,
    tc: pb_wkt.Any,
    result: harness_pb.TestResult,
    google_pool: descriptor_pool.DescriptorPool | None = None,
) -> harness_pb.TestResult:
    type_name = tc.type_url.split("/")[-1]
    msg: protobuf.Message | google_message.Message
    if google_pool is not None:
        try:
            google_desc = google_pool.FindMessageTypeByName(type_name)
        except KeyError:
            result.result = Oneof(field="unexpected_error", value=f"unknown type: {type_name}")
            return result
        msg = message_factory.GetMessageClass(google_desc)()
        msg.ParseFromString(tc.value)
    else:
        desc = registry.message(type_name)
        if desc is None:
            result.result = Oneof(field="unexpected_error", value=f"unknown type: {type_name}")
            return result
        unpacked = tc.unpack(desc)
        if unpacked is None:
            result.result = Oneof(field="unexpected_error", value=f"cannot unpack {tc.type_url}")
            return result
        msg = unpacked
    return run_test_case(validator, msg, result)


def run_conformance_test(
    request: harness_pb.TestConformanceRequest,
) -> harness_pb.TestConformanceResponse:
    registry = request.fdset.to_registry()
    # The registry resolves the conformance suite's custom predefined-rule extensions.
    validator = protovalidate.Validator(registry=registry)
    google_pool = build_google_pool(request.fdset) if _LEGACY else None
    response = harness_pb.TestConformanceResponse()
    for name, tc in request.cases.items():
        response.results[name] = run_any_test_case(validator, registry, tc, harness_pb.TestResult(), google_pool)
    return response


if __name__ == "__main__":
    # Read a serialized TestConformanceRequest from stdin
    request = harness_pb.TestConformanceRequest.from_binary(sys.stdin.buffer.read())
    # Run the test
    result = run_conformance_test(request)
    # Write a serialized TestConformanceResponse to stdout
    sys.stdout.buffer.write(result.to_binary())
    sys.stdout.flush()
    sys.exit(0)
