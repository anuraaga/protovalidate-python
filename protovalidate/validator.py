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

import protobuf
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

from buf.validate import validate_pb2
from protovalidate.internal import extra_func
from protovalidate.internal import rules as _rules

CompilationError = _rules.CompilationError
Violations = validate_pb2.Violations
Violation = _rules.Violation


class Validator:
    """
    Validates protobuf-py messages against static rules.

    Each validator instance caches internal state generated from the static
    rules, so reusing the same instance for multiple validations
    significantly improves performance.

    The rule engine evaluates CEL through cel-expr-python, which only ingests
    ``google.protobuf`` descriptor pools and messages. Each validated message
    type is therefore mirrored once into a private ``google.protobuf`` pool
    (cold path), and every validated message crosses the boundary by a
    serialize/parse round trip (hot path).
    """

    _factory: _rules.RuleFactory

    def __init__(self):
        # The bridge pool must be the process-wide default: google.protobuf
        # parses descriptor options (where validation rules live) against the
        # default pool only, so extensions mirrored anywhere else — notably
        # predefined rules — would come back as unknown fields. The mirror
        # therefore mutates global state, skipping files already present.
        self._pool = descriptor_pool.Default()
        self._factory = _rules.RuleFactory(extra_func.make_extension(), self._pool)
        self._mirrored: set[str] = set()
        self._classes: dict[str, type] = {}

    def _bridge(self, message: protobuf.Message):
        """Re-creates a protobuf-py message as a google.protobuf message."""
        desc = type(message).desc()
        cls = self._classes.get(desc.type_name)
        if cls is None:
            self._mirror_file(desc.file)
            google_desc = self._pool.FindMessageTypeByName(desc.type_name)
            cls = message_factory.GetMessageClass(google_desc)
            self._classes[desc.type_name] = cls
        bridged = cls()
        bridged.ParseFromString(message.to_binary())
        return bridged

    def _mirror_file(self, desc_file) -> None:
        if desc_file.name in self._mirrored:
            return
        # Proto imports are acyclic; dependencies register first.
        for dep in desc_file.dependencies:
            self._mirror_file(dep)
        try:
            self._pool.FindFileByName(desc_file.name)
        except KeyError:
            proto = descriptor_pb2.FileDescriptorProto.FromString(desc_file.proto.to_binary())
            self._pool.Add(proto)
        self._mirrored.add(desc_file.name)

    def validate(self, message: protobuf.Message, *, fail_fast: bool = False):
        """
        Validates the given message against the static rules defined in
        the message's descriptor.

        Parameters:
            message: The message to validate.
            fail_fast: If true, validation will stop after the first iteration.
        Raises:
            CompilationError: If the static rules could not be compiled.
            ValidationError: If the message is invalid. The violations raised as part of this error should
            always be equal to the list of violations returned by `collect_violations`.
        """
        violations = self.collect_violations(message, fail_fast=fail_fast)
        if len(violations) > 0:
            msg = f"invalid {type(message).desc().name}"
            raise ValidationError(msg, violations)

    def collect_violations(
        self,
        message: protobuf.Message,
        *,
        fail_fast: bool = False,
    ) -> list[Violation]:
        """
        Validates the given message against the static rules defined in
        the message's descriptor. Compared to `validate`, `collect_violations` simply
        returns the violations as a list and puts the burden of raising an appropriate
        exception on the caller.

        The violations returned from this method should always be equal to the violations
        raised as part of the ValidationError in the call to `validate`.

        Parameters:
            message: The message to validate.
            fail_fast: If true, validation will stop after the first iteration.
        Raises:
            CompilationError: If the static rules could not be compiled.
        """
        bridged = self._bridge(message)
        ctx = _rules.RuleContext(fail_fast=fail_fast)
        for rule in self._factory.get(bridged.DESCRIPTOR):
            rule.validate(ctx, bridged)
            if ctx.done:
                break
        for violation in ctx.violations:
            if violation.proto.HasField("field"):
                violation.proto.field.elements.reverse()
            if violation.proto.HasField("rule"):
                violation.proto.rule.elements.reverse()
        return ctx.violations


class ValidationError(ValueError):
    """
    An error raised when a message fails to validate.
    """

    _violations: list[_rules.Violation]

    def __init__(self, msg: str, violations: list[_rules.Violation]):
        super().__init__(msg)
        self._violations = violations

    def to_proto(self) -> validate_pb2.Violations:
        """
        Provides the Protobuf form of the validation errors.
        """
        return validate_pb2.Violations(violations=[violation.proto for violation in self._violations])

    @property
    def violations(self) -> list[Violation]:
        """
        Provides the validation errors as a simple Python list, rather than the
        Protobuf-specific collection type used by Violations.
        """
        return self._violations
