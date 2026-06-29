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

from collections.abc import Iterable, MutableMapping
from itertools import chain
from pathlib import Path
from typing import Any

import pytest
from cel_expr_python import cel
from cel_expr_python.ext import ext_strings
from google.protobuf import descriptor_pool, text_format

from .gen.cel.expr import eval_pb2
from .gen.cel.expr.conformance.test import simple_pb2

# Version of the cel-spec that this implementation is conformant with.
CEL_SPEC_VERSION = "v0.25.1"

# Supplemental (non cel-spec) format cases where the runtime's builtin
# diverges from the previous celpy-based implementation. The invalid-UTF-8
# cases expect bytes formatted with %s to be replaced with U+FFFD; the runtime
# instead produces a CEL string containing the invalid bytes verbatim, which
# cannot even be converted to a Python str.
skipped_tests = [
    "bytes support for string with invalid utf-8 encoding",
    "bytes support for string with only invalid utf-8 sequences",
]

# Supplemental error cases that expect formatting an object to fail. The
# runtime implements the current CEL spec for format, which formats proto
# messages (e.g. a Duration renders as "2s") instead of erroring.
error_skipped_tests = [
    "object not allowed",
    "object inside list",
    "object inside map",
]


def load_test_data(file_name: str) -> simple_pb2.SimpleTestFile:
    msg = simple_pb2.SimpleTestFile()
    with open(file_name) as file:
        text_data = file.read()
        text_format.Parse(text_data, msg)
    return msg


def build_variables(bindings: MutableMapping[str, eval_pb2.ExprValue]) -> dict[Any, Any]:
    binder = {}
    for key, value in bindings.items():
        if value.HasField("value"):
            val = value.value
            if val.HasField("string_value"):
                binder[key] = val.string_value
    return binder


def get_expected_result(test: simple_pb2.SimpleTest) -> str | None:
    if test.HasField("value"):
        val = test.value
        if val.HasField("string_value"):
            return val.string_value
    return None


# The test data from the cel-spec conformance tests
testdata_dir = Path(__file__).parent / "testdata"
cel_test_data = load_test_data(testdata_dir / f"string_ext_{CEL_SPEC_VERSION}.textproto")
# Our supplemental tests of functionality not in the cel conformance file, but defined in the spec.
supplemental_test_data = load_test_data(testdata_dir / "string_ext_supplemental.textproto")

# Combine the test data from both files into one
sections = cel_test_data.section
sections.extend(supplemental_test_data.section)

# Find the format tests which test successful formatting
_format_tests: Iterable[simple_pb2.SimpleTest] = chain.from_iterable(x.test for x in sections if x.name == "format")
# Find the format error tests which test errors during formatting
_format_error_tests: Iterable[simple_pb2.SimpleTest] = chain.from_iterable(
    x.test for x in sections if x.name == "format_errors"
)

# The bundled strings extension provides string.format, so an environment with
# just that extension exercises the same implementation protovalidate relies
# on. The fixture expressions reference free variables, so the type check is
# disabled and bindings resolve at evaluation time.
env = cel.NewEnv(descriptor_pool=descriptor_pool.Default(), extensions=[ext_strings.ExtStrings()])


def test_format_successes(subtests: pytest.Subtests):
    """Tests success scenarios for string.format using the runtime builtin."""
    for format_test in _format_tests:
        with subtests.test(msg=format_test.name):
            if format_test.name in skipped_tests:
                pytest.skip(f"runtime builtin diverges from supplemental fixture: {format_test.name}")
            program = env.compile(format_test.expr, disable_check=True)
            bindings = build_variables(format_test.bindings)
            result = program.eval(data=bindings)
            expected = get_expected_result(format_test)
            assert expected is not None, f"[{format_test.name}]: expected a success result to be defined"
            assert result.plain_value() == expected


def test_format_errors(subtests: pytest.Subtests):
    """Tests error scenarios for string.format using the runtime builtin.

    The cel-spec fixtures pin exact error messages that are tied to the
    reference implementation; the runtime's wording differs, so we only assert
    that evaluation produces an error, which is the behavior the spec defines.
    """
    for format_error_test in _format_error_tests:
        with subtests.test(msg=format_error_test.name):
            if format_error_test.name in error_skipped_tests:
                pytest.skip(f"runtime builtin diverges from supplemental fixture: {format_error_test.name}")
            program = env.compile(format_error_test.expr, disable_check=True)
            bindings = build_variables(format_error_test.bindings)
            result = program.eval(data=bindings)
            assert result.type() == cel.Type.ERROR
