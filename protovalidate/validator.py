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

from protobuf import Message, Registry

from protovalidate._gen.buf.validate import validate_pb
from protovalidate.internal import extra_func
from protovalidate.internal import rules as _rules

CompilationError = _rules.CompilationError
Violations = validate_pb.Violations
Violation = _rules.Violation


class Validator:
    """
    Validates protobuf-py messages against static rules.

    Each validator instance caches internal state generated from the static
    rules, so reusing the same instance for multiple validations
    significantly improves performance.
    """

    _factory: _rules.RuleFactory

    def __init__(self, registry: Registry | None = None):
        """
        Parameters:
            registry: An optional protobuf-py Registry used to resolve custom
                predefined-rule extensions (proto2 extensions on the standard
                rule messages). Without it, only standard rules and rules whose
                extensions are known to the bundled stub are applied.
        """
        funcs = extra_func.make_extra_funcs()
        self._factory = _rules.RuleFactory(funcs, registry)

    def validate(self, message: Message, *, fail_fast: bool = False):
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
        message: Message,
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
        ctx = _rules.RuleContext(fail_fast=fail_fast)
        for rule in self._factory.get(type(message).desc()):
            rule.validate(ctx, message)
            if ctx.done:
                break
        for violation in ctx.violations:
            violation.finalize_paths()
        return ctx.violations


class ValidationError(ValueError):
    """
    An error raised when a message fails to validate.
    """

    _violations: list[_rules.Violation]

    def __init__(self, msg: str, violations: list[_rules.Violation]):
        super().__init__(msg)
        self._violations = violations

    def to_proto(self) -> validate_pb.Violations:
        """
        Provides the Protobuf form of the validation errors.
        """
        return validate_pb.Violations(violations=[violation.proto for violation in self._violations])

    @property
    def violations(self) -> list[Violation]:
        """
        Provides the validation errors as a simple Python list, rather than the
        Protobuf-specific collection type used by Violations.
        """
        return self._violations
