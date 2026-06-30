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
from protobuf import Oneof, Registry
from protobuf import wkt as pb_wkt

import protovalidate
from buf.validate import validate_pb
from buf.validate.conformance.harness import harness_pb


def run_test_case(tc: protobuf.Message, result: harness_pb.TestResult) -> harness_pb.TestResult:
    # Run the validator
    try:
        violations = protovalidate.collect_violations(tc)
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
    registry: Registry,
    tc: pb_wkt.Any,
    result: harness_pb.TestResult,
) -> harness_pb.TestResult:
    type_name = tc.type_url.split("/")[-1]
    desc = registry.message(type_name)
    if desc is None:
        result.result = Oneof(field="unexpected_error", value=f"unknown type: {type_name}")
        return result
    msg = tc.unpack(desc)
    if msg is None:
        result.result = Oneof(field="unexpected_error", value=f"cannot unpack {tc.type_url}")
        return result
    return run_test_case(msg, result)


def run_conformance_test(
    request: harness_pb.TestConformanceRequest,
) -> harness_pb.TestConformanceResponse:
    registry = request.fdset.to_registry()
    response = harness_pb.TestConformanceResponse()
    for name, tc in request.cases.items():
        response.results[name] = run_any_test_case(registry, tc, harness_pb.TestResult())
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
