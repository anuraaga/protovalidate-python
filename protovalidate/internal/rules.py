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

"""The rule engine.

This is the celpy (pure-Python CEL) engine wired to protobuf-py: rules are
discovered from protobuf-py descriptors (buf.validate options read via the
relocatable ``validate_pb`` stub), message values are converted to celpy
``celtypes`` for evaluation, and violations are emitted as protobuf-py
``validate_pb`` messages. There is no google.protobuf dependency.
"""

import abc
import dataclasses
import datetime
import typing
from collections.abc import Callable, Mapping

import celpy
from celpy import celtypes
from protobuf import (
    DescEnum,
    DescExtension,
    DescField,
    DescFieldValueEnum,
    DescFieldValueList,
    DescFieldValueMap,
    DescFieldValueMessage,
    DescMessage,
    DescOneof,
    Extension,
    Message,
    Oneof,
    Registry,
    ScalarType,
    wkt,
)

from protovalidate._gen.buf.validate import validate_pb
from protovalidate.internal.cel_field_presence import InterpretedRunner, in_has

# FieldDescriptorProto.Type numbers (shared between google and protobuf-py).
_TYPE_MESSAGE = 11
_TYPE_GROUP = 10
_TYPE_ENUM = 14


class CompilationError(Exception):
    pass


# ----- field type metadata, keyed on the wire type number -----


class _FieldTypeMeta(typing.TypedDict):
    name: str
    ctor: Callable[..., celtypes.Value]


def _msg_to_cel(msg: Message) -> celtypes.Value:
    ctor = _WKT_CTORS.get(type(msg).desc().type_name)
    if ctor is not None:
        return ctor(msg)
    return MessageType(msg)


_TYPE_META: dict[int, _FieldTypeMeta] = {
    _TYPE_MESSAGE: {"name": "message", "ctor": _msg_to_cel},
    _TYPE_GROUP: {"name": "group", "ctor": _msg_to_cel},
    _TYPE_ENUM: {"name": "enum", "ctor": lambda v: celtypes.IntType(int(v))},
    8: {"name": "bool", "ctor": celtypes.BoolType},
    12: {"name": "bytes", "ctor": celtypes.BytesType},
    9: {"name": "string", "ctor": celtypes.StringType},
    2: {"name": "float", "ctor": celtypes.DoubleType},
    1: {"name": "double", "ctor": celtypes.DoubleType},
    5: {"name": "int32", "ctor": celtypes.IntType},
    3: {"name": "int64", "ctor": celtypes.IntType},
    17: {"name": "sint32", "ctor": celtypes.IntType},
    18: {"name": "sint64", "ctor": celtypes.IntType},
    15: {"name": "sfixed32", "ctor": celtypes.IntType},
    16: {"name": "sfixed64", "ctor": celtypes.IntType},
    13: {"name": "uint32", "ctor": celtypes.UintType},
    4: {"name": "uint64", "ctor": celtypes.UintType},
    7: {"name": "fixed32", "ctor": celtypes.UintType},
    6: {"name": "fixed64", "ctor": celtypes.UintType},
}


def _get_type_name(type_num: int) -> str:
    meta = _TYPE_META.get(type_num)
    return meta["name"] if meta is not None else "unknown"


def _fields_by_name(desc: DescMessage) -> dict[str, DescField]:
    """A name -> field map computed from the public field list (protobuf-py
    descriptors do not expose a public fields_by_name)."""
    return {field.name: field for field in desc.fields}


def _scalar_zero(type_num: int) -> str | bytes | bool | float | int:
    if type_num == 9:
        return ""
    if type_num == 12:
        return b""
    if type_num == 8:
        return False
    if type_num in (1, 2):
        return 0.0
    return 0


# ----- _Field: a uniform view over a protobuf-py DescField or a synthetic
# map-key / map-value / list-item field (which protobuf-py does not model as
# its own descriptor). -----


class _Field:
    __slots__ = (
        "desc",
        "enum",
        "has_presence",
        "is_map",
        "is_repeated",
        "item_field",
        "key_field",
        "local_name",
        "message",
        "name",
        "number",
        "type",
        "value_field",
    )

    def __init__(
        self,
        *,
        desc: DescField | Extension | None = None,
        type: int,  # noqa: A002
        name: str = "",
        number: int = 0,
        local_name: str = "",
        message: DescMessage | None = None,
        enum: DescEnum | None = None,
        has_presence: bool = False,
        is_repeated: bool = False,
        is_map: bool = False,
        item_field: "_Field | None" = None,
        key_field: "_Field | None" = None,
        value_field: "_Field | None" = None,
    ):
        self.desc = desc
        self.type = type
        self.name = name
        self.number = number
        self.local_name = local_name
        self.message = message
        self.enum = enum
        self.has_presence = has_presence
        self.is_repeated = is_repeated
        self.is_map = is_map
        self.item_field = item_field
        self.key_field = key_field
        self.value_field = value_field

    @property
    def message_full_name(self) -> str | None:
        return self.message.type_name if self.message is not None else None

    def get(self, msg: Message) -> typing.Any:
        # Item access (by descriptor) reads any field kind uniformly, including
        # oneof members, which attribute access does not expose by member name.
        assert self.desc is not None  # noqa: S101
        return msg[self.desc]

    def is_present(self, msg: Message) -> bool:
        return self.desc is not None and self.desc in msg

    @classmethod
    def of(cls, desc: DescField) -> "_Field":
        value = desc.value
        type_num = int(desc.proto.type)
        # Delimited (proto2 group / editions delimited) message fields report
        # the GROUP wire type in field paths.
        if getattr(value, "delimited_encoding", False):
            type_num = _TYPE_GROUP
        if isinstance(value, DescFieldValueMap):
            return cls(
                desc=desc,
                type=type_num,
                name=desc.name,
                number=desc.number,
                local_name=desc.local_name,
                is_repeated=True,
                is_map=True,
                key_field=_leaf_field(value.key),
                value_field=_leaf_field(value.value),
            )
        if isinstance(value, DescFieldValueList):
            return cls(
                desc=desc,
                type=type_num,
                name=desc.name,
                number=desc.number,
                local_name=desc.local_name,
                is_repeated=True,
                item_field=_leaf_field(value.element, name=desc.name, number=desc.number),
            )
        message = value.message if isinstance(value, DescFieldValueMessage) else None
        enum = value.enum if isinstance(value, DescFieldValueEnum) else None
        return cls(
            desc=desc,
            type=type_num,
            name=desc.name,
            number=desc.number,
            local_name=desc.local_name,
            message=message,
            enum=enum,
            has_presence=desc.presence.name != "IMPLICIT",
        )

    @classmethod
    def of_extension(cls, ext: DescExtension) -> "_Field":
        """A _Field for a proto2 extension on a rules message (read via the
        Extension object; the path uses the bracketed extension name)."""
        value = ext.value
        type_num = int(ext.proto.type)
        if getattr(value, "delimited_encoding", False):
            type_num = _TYPE_GROUP
        name = f"[{ext.type_name}]"
        if isinstance(value, DescFieldValueList):
            return cls(
                desc=ext.type,
                type=type_num,
                name=name,
                number=ext.number,
                is_repeated=True,
                item_field=_leaf_field(value.element, name=name, number=ext.number),
            )
        message = value.message if isinstance(value, DescFieldValueMessage) else None
        enum = value.enum if isinstance(value, DescFieldValueEnum) else None
        return cls(
            desc=ext.type,
            type=type_num,
            name=name,
            number=ext.number,
            message=message,
            enum=enum,
            has_presence=True,
        )


def _leaf_field(kind: ScalarType | DescMessage | DescEnum, *, name: str = "", number: int = 0) -> _Field:
    """Builds a synthetic _Field for a map key/value or list element kind."""
    if isinstance(kind, ScalarType):
        return _Field(type=int(kind), name=name, number=number)
    if isinstance(kind, DescMessage):
        return _Field(type=_TYPE_MESSAGE, name=name, number=number, message=kind)
    if isinstance(kind, DescEnum):
        return _Field(type=_TYPE_ENUM, name=name, number=number, enum=kind)
    msg = "unknown map/list element kind"
    raise CompilationError(msg)


# ----- value conversion: protobuf-py -> celpy celtypes -----


def make_duration(msg: wkt.duration_pb.Duration) -> celtypes.DurationType:
    return celtypes.DurationType(seconds=msg.seconds, nanos=msg.nanos)


def make_timestamp(msg: wkt.timestamp_pb.Timestamp) -> celtypes.TimestampType:
    return celtypes.TimestampType(1970, 1, 1) + celtypes.DurationType(seconds=msg.seconds, nanos=msg.nanos)


def _unwrap(msg: Message) -> celtypes.Value:
    value_field = _Field.of(_fields_by_name(type(msg).desc())["value"])
    return _scalar_to_cel(value_field.get(msg), value_field)


_WKT_CTORS: dict[str, Callable[..., celtypes.Value]] = {
    "google.protobuf.Duration": make_duration,
    "google.protobuf.Timestamp": make_timestamp,
    "google.protobuf.StringValue": _unwrap,
    "google.protobuf.BytesValue": _unwrap,
    "google.protobuf.Int32Value": _unwrap,
    "google.protobuf.Int64Value": _unwrap,
    "google.protobuf.UInt32Value": _unwrap,
    "google.protobuf.UInt64Value": _unwrap,
    "google.protobuf.FloatValue": _unwrap,
    "google.protobuf.DoubleValue": _unwrap,
    "google.protobuf.BoolValue": _unwrap,
}


def _scalar_to_cel(val: typing.Any, field: _Field) -> celtypes.Value:
    meta = _TYPE_META.get(field.type)
    if meta is None:
        msg = "unknown field type"
        raise CompilationError(msg)
    return meta["ctor"](val)


def _map_to_cel(mapping: Mapping[typing.Any, typing.Any], field: _Field) -> celtypes.Value:
    key_field, value_field = field.key_field, field.value_field
    assert key_field is not None and value_field is not None  # noqa: S101
    result = celtypes.MapType()
    for key, val in mapping.items():
        result[_scalar_to_cel(key, key_field)] = _scalar_to_cel(val, value_field)
    return result


def _field_value_to_cel(val: typing.Any, field: _Field) -> celtypes.Value:
    if field.is_map:
        return _map_to_cel(val, field)
    if field.is_repeated:
        item_field = field.item_field
        assert item_field is not None  # noqa: S101
        return celtypes.ListType(_scalar_to_cel(item, item_field) for item in val)
    return _scalar_to_cel(val, field)


def field_to_cel(msg: Message, field: _Field) -> celtypes.Value:
    if field.is_repeated:
        return _field_value_to_cel(field.get(msg), field)
    if field.message is not None and not field.is_present(msg):
        return None
    return _scalar_to_cel(field.get(msg), field)


def _zero_value(field: _Field) -> celtypes.Value:
    if field.message is not None and not field.is_repeated:
        return _msg_to_cel(field.message.type())
    return _scalar_to_cel(_scalar_zero(field.type), field)


def _is_empty_field(msg: Message, field: _Field) -> bool:
    if field.has_presence:
        return not field.is_present(msg)
    if field.is_repeated:
        return len(field.get(msg)) == 0
    return field.get(msg) == _scalar_zero(field.type)


class MessageType(celtypes.MapType):
    msg: Message

    def __init__(self, msg: Message):
        super().__init__()
        self.msg = msg
        self.desc = type(msg).desc()
        self.fields_by_name = _fields_by_name(self.desc)
        self._oneof_field_names = {f.name for oneof in self.desc.oneofs for f in oneof.fields}
        for fdesc in self.desc.fields:
            if fdesc.name in self._oneof_field_names and fdesc not in msg:
                continue
            self[fdesc.name] = field_to_cel(msg, _Field.of(fdesc))

    def __getitem__(self, key):
        fdesc = self.fields_by_name[key]
        field = _Field.of(fdesc)
        if field.has_presence and fdesc not in self.msg:
            if in_has():
                raise KeyError
            return _zero_value(field)
        return super().__getitem__(key)


# ----- protobuf-py validate_pb path / element construction -----


def _ftype(type_num: int) -> wkt.descriptor_pb.FieldDescriptorProto.Type:
    return wkt.descriptor_pb.FieldDescriptorProto.Type(type_num)


def _field_to_element(field: _Field) -> validate_pb.FieldPathElement:
    return validate_pb.FieldPathElement(
        field_number=field.number,
        field_name=field.name,
        field_type=_ftype(field.type),
    )


def _indexed_field_element(field: _Field, index: int) -> validate_pb.FieldPathElement:
    return validate_pb.FieldPathElement(
        field_number=field.number,
        field_name=field.name,
        field_type=_ftype(field.type),
        subscript=Oneof(field="index", value=index),
    )


def _oneof_to_element(oneof: DescOneof) -> validate_pb.FieldPathElement:
    return validate_pb.FieldPathElement(field_name=oneof.name)


_INT_KEY_TYPES = frozenset((5, 15, 3, 16, 17, 18))
_UINT_KEY_TYPES = frozenset((13, 7, 4, 6))


def _map_key_element(field: _Field, key: typing.Any) -> validate_pb.FieldPathElement:
    key_field, value_field = field.key_field, field.value_field
    assert key_field is not None and value_field is not None  # noqa: S101
    key_type = key_field.type
    subscript: Oneof
    if key_type == 8:
        subscript = Oneof(field="bool_key", value=key)
    elif key_type in _INT_KEY_TYPES:
        subscript = Oneof(field="int_key", value=key)
    elif key_type in _UINT_KEY_TYPES:
        subscript = Oneof(field="uint_key", value=key)
    elif key_type == 9:
        subscript = Oneof(field="string_key", value=key)
    else:
        msg = "unexpected map type"
        raise CompilationError(msg)
    return validate_pb.FieldPathElement(
        field_number=field.number,
        field_name=field.name,
        field_type=_ftype(field.type),
        key_type=_ftype(key_type),
        value_type=_ftype(value_field.type),
        subscript=subscript,
    )


def _spec_field(rules_cls: type[Message], name: str) -> DescField:
    return _fields_by_name(rules_cls.desc())[name]


def _spec_element(pb_field: DescField) -> validate_pb.FieldPathElement:
    return validate_pb.FieldPathElement(
        field_number=pb_field.number,
        field_name=pb_field.name,
        field_type=pb_field.proto.type,
    )


def _indexed_spec_element(pb_field: DescField, index: int) -> validate_pb.FieldPathElement:
    return validate_pb.FieldPathElement(
        field_number=pb_field.number,
        field_name=pb_field.name,
        field_type=pb_field.proto.type,
        subscript=Oneof(field="index", value=index),
    )


def _which_type(field_level: validate_pb.FieldRules) -> str | None:
    return field_level.type.field if field_level.type is not None else None


class Violation:
    """A singular rule violation.

    Field/rule paths accumulate as element lists during recursion (protobuf-py
    messages are immutable and do not auto-vivify), materialized into a
    ``validate_pb.Violation`` lazily via :attr:`proto`.
    """

    field_value: typing.Any
    rule_value: typing.Any

    def __init__(
        self,
        *,
        field_value: typing.Any = None,
        rule_value: typing.Any = None,
        field: validate_pb.FieldPath | None = None,
        rule: validate_pb.FieldPath | None = None,
        rule_id: str = "",
        message: str = "",
        for_key: bool = False,
    ):
        self.field_value = field_value
        self.rule_value = rule_value
        self._field_elements: list[validate_pb.FieldPathElement] = list(field.elements) if field is not None else []
        self._rule_elements: list[validate_pb.FieldPathElement] = list(rule.elements) if rule is not None else []
        self._rule_id = rule_id
        self._message = message
        self._for_key = for_key

    def append_field_element(self, element: validate_pb.FieldPathElement) -> None:
        self._field_elements.append(element)

    def extend_rule_elements(self, elements: list[validate_pb.FieldPathElement]) -> None:
        self._rule_elements.extend(elements)

    def finalize_paths(self) -> None:
        self._field_elements.reverse()
        self._rule_elements.reverse()

    @property
    def proto(self) -> validate_pb.Violation:
        kwargs: dict[str, typing.Any] = {
            "rule_id": self._rule_id,
            "message": self._message,
            "for_key": self._for_key,
        }
        if self._field_elements:
            kwargs["field"] = validate_pb.FieldPath(elements=list(self._field_elements))
        if self._rule_elements:
            kwargs["rule"] = validate_pb.FieldPath(elements=list(self._rule_elements))
        return validate_pb.Violation(**kwargs)


class RuleContext:
    """The state associated with a single rule evaluation."""

    _violations: list[Violation]

    def __init__(self, *, fail_fast: bool = False):
        self._fail_fast = fail_fast
        self._violations = []

    @property
    def violations(self) -> list[Violation]:
        return self._violations

    def add(self, violation: Violation):
        self._violations.append(violation)

    def add_errors(self, other_ctx: "RuleContext"):
        self._violations.extend(other_ctx.violations)

    def add_field_path_element(self, element: validate_pb.FieldPathElement):
        for violation in self._violations:
            violation.append_field_element(element)

    def add_rule_path_elements(self, elements: list[validate_pb.FieldPathElement]):
        for violation in self._violations:
            violation.extend_rule_elements(elements)

    @property
    def done(self) -> bool:
        return self._fail_fast and self.has_errors()

    def has_errors(self) -> bool:
        return len(self._violations) > 0

    def sub_context(self) -> "RuleContext":
        return RuleContext(fail_fast=self._fail_fast)


class Rules(abc.ABC):
    """The rules associated with a single 'rules' message."""

    @abc.abstractmethod
    def validate(self, ctx: RuleContext, message: Message) -> None:
        """Validate the message against the rules in this rule."""
        ...


@dataclasses.dataclass
class CelRunner:
    runner: celpy.Runner
    rule: validate_pb.Rule
    rule_value: typing.Any | None = None
    rule_cel: celtypes.Value | None = None
    rule_path: validate_pb.FieldPath | None = None


class CelRules(Rules):
    """A rule that has rules written in CEL."""

    _cel: list[CelRunner]
    _rules: Message | None = None
    _rules_cel: celtypes.Value | None = None
    _uses_now: bool = False

    def __init__(self, rules: Message | None):
        self._cel = []
        if rules is not None:
            self._rules = rules
            self._rules_cel = _msg_to_cel(rules)

    def _validate_cel(
        self,
        ctx: RuleContext,
        *,
        this_value: typing.Any | None = None,
        this_cel: celtypes.Value | None = None,
        for_key: bool = False,
    ):
        if not self._cel:
            return
        activation: dict[str, celtypes.Value] = {}
        if this_cel is not None:
            activation["this"] = this_cel
        activation["rules"] = self._rules_cel
        if self._uses_now:
            activation["now"] = celtypes.TimestampType(datetime.datetime.now(tz=datetime.timezone.utc))
        for cel in self._cel:
            activation["rule"] = cel.rule_cel
            result = cel.runner.evaluate(activation)
            if isinstance(result, celtypes.BoolType):
                if not result:
                    message = cel.rule.message
                    if len(message) == 0:
                        message = f'"{cel.rule.expression}" returned false'
                    ctx.add(
                        Violation(
                            field_value=this_value,
                            rule=cel.rule_path,
                            rule_value=cel.rule_value,
                            rule_id=cel.rule.id,
                            message=message,
                            for_key=for_key,
                        ),
                    )
            elif isinstance(result, celtypes.StringType):
                if result:
                    ctx.add(
                        Violation(
                            field_value=this_value,
                            rule=cel.rule_path,
                            rule_value=cel.rule_value,
                            rule_id=cel.rule.id,
                            message=result,
                            for_key=for_key,
                        ),
                    )
            elif isinstance(result, Exception):
                raise result

    def add_rule(
        self,
        env: celpy.Environment,
        funcs: dict[str, celpy.CELFunction],
        rules: validate_pb.Rule | str,
        *,
        rule_field: _Field | None = None,
        rule_path: validate_pb.FieldPath | None = None,
    ):
        if isinstance(rules, str):
            expression = rules
            rules = validate_pb.Rule(id=expression, expression=expression)
        if "now" in rules.expression:
            self._uses_now = True
        ast = env.compile(rules.expression)
        prog = env.program(ast, functions=funcs)
        rule_value = None
        rule_cel = None
        if rule_field is not None and self._rules is not None:
            rule_value = rule_field.get(self._rules)
            rule_cel = field_to_cel(self._rules, rule_field)
        self._cel.append(
            CelRunner(
                runner=prog,
                rule=rules,
                rule_value=rule_value,
                rule_cel=rule_cel,
                rule_path=rule_path,
            )
        )


class MessageOneofRule(Rules):
    """Validates a single buf.validate.MessageOneofRule given via the (buf.validate.message).oneof option."""

    def __init__(self, fields: list[_Field], *, required: bool):
        self._fields = fields
        self._required = required

    def validate(self, ctx: RuleContext, message: Message):
        num_set_fields = sum(1 for field in self._fields if not _is_empty_field(message, field))
        if num_set_fields > 1:
            ctx.add(
                Violation(
                    rule_id="message.oneof",
                    message=f"only one of {', '.join(field.name for field in self._fields)} can be set",
                )
            )
        if self._required and num_set_fields == 0:
            ctx.add(
                Violation(
                    rule_id="message.oneof",
                    message=f"one of {', '.join(field.name for field in self._fields)} must be set",
                )
            )


class MessageRules(CelRules):
    """Message-level rules."""

    _oneofs: list[MessageOneofRule]

    def __init__(self, rules: Message | None, desc: DescMessage):
        super().__init__(rules)
        self._oneofs = []
        self._desc = desc

    def validate(self, ctx: RuleContext, message: Message):
        if self._cel:
            self._validate_cel(ctx, this_cel=_msg_to_cel(message))
            if ctx.done:
                return
        for oneof in self._oneofs:
            oneof.validate(ctx, message)
            if ctx.done:
                return

    def add_oneof(self, rule: validate_pb.MessageOneofRule):
        fields = []
        seen = set()
        if len(rule.fields) == 0:
            msg = f"at least one field must be specified in oneof rule for the message {self._desc.type_name}"
            raise CompilationError(msg)
        desc_fields = _fields_by_name(self._desc)
        for name in rule.fields:
            if name in desc_fields:
                if name in seen:
                    msg = f"duplicate {name} in oneof rule for the message {self._desc.type_name}"
                    raise CompilationError(msg)
                fields.append(_Field.of(desc_fields[name]))
                seen.add(name)
            else:
                msg = f'field "{name}" not found in message {self._desc.type_name}'
                raise CompilationError(msg)
        self._oneofs.append(MessageOneofRule(fields, required=rule.required))


def check_field_type(field: _Field, expected: int, wrapper_name: str | None = None):
    if field.type != expected and (field.type != _TYPE_MESSAGE or field.message_full_name != wrapper_name):
        field_type_str = _get_type_name(field.type)
        if expected == 0:
            expected_type_str = wrapper_name if wrapper_name is not None else _get_type_name(_TYPE_MESSAGE)
        else:
            expected_type_str = _get_type_name(expected)
        msg = f"field {field.name} has type {field_type_str} but expected {expected_type_str}"
        raise CompilationError(msg)


class FieldRules(CelRules):
    """Field-level rules."""

    _ignore_empty = False
    _required = False

    _required_rule_path: typing.ClassVar[validate_pb.FieldPath] = validate_pb.FieldPath(
        elements=[_spec_element(_spec_field(validate_pb.FieldRules, "required"))]
    )

    def __init__(
        self,
        env: celpy.Environment,
        funcs: dict[str, celpy.CELFunction],
        field: _Field,
        field_level: validate_pb.FieldRules,
        *,
        for_items: bool = False,
        force_ignore_empty: bool = False,
        registry: Registry | None = None,
    ):
        type_oneof = field_level.type
        type_case = type_oneof.field if type_oneof is not None else None
        rules_pb = type_oneof.value if type_oneof is not None else None
        super().__init__(rules_pb)
        self._field = field
        self._ignore_empty = (
            field_level.ignore == validate_pb.Ignore.IF_ZERO_VALUE
            or force_ignore_empty
            or (field.has_presence and not for_items)
        )
        self._required = field_level.required
        if rules_pb is not None:
            assert type_case is not None  # noqa: S101
            type_field = _spec_field(validate_pb.FieldRules, type_case)
            # For each set rule sub-field, look for the private predefined-rule
            # extension that implements it. Standard rules carry these as
            # declared fields known to the bundled stub.
            for rule_field_desc in type(rules_pb).desc().fields:
                if rule_field_desc not in rules_pb:
                    continue
                opts = rule_field_desc.proto.options
                if opts is None or validate_pb.ext_predefined not in opts:
                    continue
                for cel in opts[validate_pb.ext_predefined].cel:
                    self.add_rule(
                        env,
                        funcs,
                        cel,
                        rule_field=_Field.of(rule_field_desc),
                        rule_path=validate_pb.FieldPath(
                            elements=[_spec_element(rule_field_desc), _spec_element(type_field)]
                        ),
                    )
            # Custom predefined rules are proto2 extensions on the rules message
            # that the bundled stub cannot decode; a caller-supplied Registry
            # knows them, so apply each extension of this rules message that is
            # set and carries a predefined rule.
            if registry is not None:
                rules_type_name = type(rules_pb).desc().type_name
                for ext in registry:
                    if (
                        not isinstance(ext, DescExtension)
                        or ext.extendee.type_name != rules_type_name
                        or ext.proto.options is None
                        or validate_pb.ext_predefined not in ext.proto.options
                        or ext.type not in rules_pb
                    ):
                        continue
                    ext_field = _Field.of_extension(ext)
                    for cel in ext.proto.options[validate_pb.ext_predefined].cel:
                        self.add_rule(
                            env,
                            funcs,
                            cel,
                            rule_field=ext_field,
                            rule_path=validate_pb.FieldPath(
                                elements=[_field_to_element(ext_field), _spec_element(type_field)]
                            ),
                        )
        cel_expression_field = _spec_field(validate_pb.FieldRules, "cel_expression")
        for i, cel in enumerate(field_level.cel_expression):
            self.add_rule(
                env,
                funcs,
                cel,
                rule_path=validate_pb.FieldPath(elements=[_indexed_spec_element(cel_expression_field, i)]),
            )
        cel_field = _spec_field(validate_pb.FieldRules, "cel")
        for i, cel in enumerate(field_level.cel):
            self.add_rule(
                env, funcs, cel, rule_path=validate_pb.FieldPath(elements=[_indexed_spec_element(cel_field, i)])
            )

    def validate(self, ctx: RuleContext, message: Message):
        if _is_empty_field(message, self._field):
            if self._required:
                ctx.add(
                    Violation(
                        field=validate_pb.FieldPath(elements=[_field_to_element(self._field)]),
                        rule=FieldRules._required_rule_path,
                        rule_value=self._required,
                        rule_id="required",
                        message="value is required",
                    ),
                )
                return
            if self._ignore_empty:
                return
        val = self._field.get(message)
        cel_val = _field_value_to_cel(val, self._field)
        sub_ctx = ctx.sub_context()
        self._validate_value(sub_ctx, val)
        self._validate_cel(sub_ctx, this_value=val, this_cel=cel_val)
        if sub_ctx.has_errors():
            sub_ctx.add_field_path_element(_field_to_element(self._field))
            ctx.add_errors(sub_ctx)

    def validate_item(self, ctx: RuleContext, value: typing.Any, item_field: _Field, *, for_key: bool = False):
        self._validate_value(ctx, value, for_key=for_key)
        self._validate_cel(ctx, this_value=value, this_cel=_scalar_to_cel(value, item_field), for_key=for_key)

    def _validate_value(self, ctx: RuleContext, value: typing.Any, *, for_key: bool = False):
        pass


class AnyRules(FieldRules):
    """Rules for an Any field."""

    _in_rule_path: typing.ClassVar[validate_pb.FieldPath] = validate_pb.FieldPath(
        elements=[
            _spec_element(_spec_field(validate_pb.AnyRules, "in")),
            _spec_element(_spec_field(validate_pb.FieldRules, "any")),
        ],
    )

    _not_in_rule_path: typing.ClassVar[validate_pb.FieldPath] = validate_pb.FieldPath(
        elements=[
            _spec_element(_spec_field(validate_pb.AnyRules, "not_in")),
            _spec_element(_spec_field(validate_pb.FieldRules, "any")),
        ],
    )

    def __init__(
        self,
        env: celpy.Environment,
        funcs: dict[str, celpy.CELFunction],
        field: _Field,
        field_level: validate_pb.FieldRules,
        *,
        registry: Registry | None = None,
    ):
        super().__init__(env, funcs, field, field_level, registry=registry)
        type_oneof = field_level.type
        assert type_oneof is not None and type_oneof.field == "any"  # noqa: S101
        any_rules = type_oneof.value
        self._in = list(any_rules.in_) or []
        self._not_in: typing.Container[str] = list(any_rules.not_in) or []

    def _validate_value(self, ctx: RuleContext, value: typing.Any, *, for_key: bool = False):
        if len(self._in) > 0 and value.type_url not in self._in:
            ctx.add(
                Violation(
                    rule=AnyRules._in_rule_path,
                    rule_value=self._in,
                    rule_id="any.in",
                    message="type URL must be in the allow list",
                    for_key=for_key,
                )
            )
        if value.type_url in self._not_in:
            ctx.add(
                Violation(
                    rule=AnyRules._not_in_rule_path,
                    rule_value=self._not_in,
                    rule_id="any.not_in",
                    message="type URL must not be in the block list",
                    for_key=for_key,
                )
            )


class EnumRules(FieldRules):
    """Rules for an enum field."""

    _defined_only = False

    _defined_only_rule_path: typing.ClassVar[validate_pb.FieldPath] = validate_pb.FieldPath(
        elements=[
            _spec_element(_spec_field(validate_pb.EnumRules, "defined_only")),
            _spec_element(_spec_field(validate_pb.FieldRules, "enum")),
        ],
    )

    def __init__(
        self,
        env: celpy.Environment,
        funcs: dict[str, celpy.CELFunction],
        field: _Field,
        field_level: validate_pb.FieldRules,
        *,
        for_items: bool = False,
        force_ignore_empty: bool = False,
        registry: Registry | None = None,
    ):
        super().__init__(
            env,
            funcs,
            field,
            field_level,
            for_items=for_items,
            force_ignore_empty=force_ignore_empty,
            registry=registry,
        )
        type_oneof = field_level.type
        assert type_oneof is not None and type_oneof.field == "enum"  # noqa: S101
        if type_oneof.value.defined_only:
            self._defined_only = True
        self._defined_numbers = {v.number for v in field.enum.values} if field.enum is not None else set()

    def validate(self, ctx: RuleContext, message: Message):
        super().validate(ctx, message)
        if ctx.done:
            return
        if self._defined_only and int(self._field.get(message)) not in self._defined_numbers:
            ctx.add(
                Violation(
                    field=validate_pb.FieldPath(elements=[_field_to_element(self._field)]),
                    rule=EnumRules._defined_only_rule_path,
                    rule_value=self._defined_only,
                    rule_id="enum.defined_only",
                    message="value must be one of the defined enum values",
                ),
            )


class RepeatedRules(FieldRules):
    """Rules for a repeated field."""

    _item_rules: FieldRules | None = None

    _items_rules_suffix: typing.ClassVar[list[validate_pb.FieldPathElement]] = [
        _spec_element(_spec_field(validate_pb.RepeatedRules, "items")),
        _spec_element(_spec_field(validate_pb.FieldRules, "repeated")),
    ]

    def __init__(
        self,
        env: celpy.Environment,
        funcs: dict[str, celpy.CELFunction],
        field: _Field,
        field_level: validate_pb.FieldRules,
        item_rules: FieldRules | None,
        *,
        registry: Registry | None = None,
    ):
        super().__init__(env, funcs, field, field_level, registry=registry)
        if item_rules is not None:
            self._item_rules = item_rules

    def validate(self, ctx: RuleContext, message: Message):
        super().validate(ctx, message)
        if ctx.done:
            return
        if self._item_rules is None:
            return
        item_field = self._field.item_field
        assert item_field is not None  # noqa: S101
        for i, item in enumerate(self._field.get(message)):
            if self._item_rules._ignore_empty and not item:
                continue
            sub_ctx = ctx.sub_context()
            self._item_rules.validate_item(sub_ctx, item, item_field)
            if sub_ctx.has_errors():
                sub_ctx.add_field_path_element(_indexed_field_element(self._field, i))
                sub_ctx.add_rule_path_elements(RepeatedRules._items_rules_suffix)
                ctx.add_errors(sub_ctx)
            if ctx.done:
                return


class MapRules(FieldRules):
    """Rules for a map field."""

    _key_rules: FieldRules | None = None
    _value_rules: FieldRules | None = None

    _key_rules_suffix: typing.ClassVar[list[validate_pb.FieldPathElement]] = [
        _spec_element(_spec_field(validate_pb.MapRules, "keys")),
        _spec_element(_spec_field(validate_pb.FieldRules, "map")),
    ]

    _value_rules_suffix: typing.ClassVar[list[validate_pb.FieldPathElement]] = [
        _spec_element(_spec_field(validate_pb.MapRules, "values")),
        _spec_element(_spec_field(validate_pb.FieldRules, "map")),
    ]

    def __init__(
        self,
        env: celpy.Environment,
        funcs: dict[str, celpy.CELFunction],
        field: _Field,
        field_level: validate_pb.FieldRules,
        key_rules: FieldRules | None,
        value_rules: FieldRules | None,
        *,
        registry: Registry | None = None,
    ):
        super().__init__(env, funcs, field, field_level, registry=registry)
        if key_rules is not None:
            self._key_rules = key_rules
        if value_rules is not None:
            self._value_rules = value_rules

    def validate(self, ctx: RuleContext, message: Message):
        super().validate(ctx, message)
        if ctx.done:
            return
        key_field = self._field.key_field
        value_field = self._field.value_field
        assert key_field is not None and value_field is not None  # noqa: S101
        for k, v in self._field.get(message).items():
            key_ctx = ctx.sub_context()
            if self._key_rules is not None and (not self._key_rules._ignore_empty or k):
                self._key_rules.validate_item(key_ctx, k, key_field, for_key=True)
                if key_ctx.has_errors():
                    key_ctx.add_rule_path_elements(MapRules._key_rules_suffix)
            map_ctx = ctx.sub_context()
            if self._value_rules is not None and (not self._value_rules._ignore_empty or v):
                self._value_rules.validate_item(map_ctx, v, value_field)
                if map_ctx.has_errors():
                    map_ctx.add_rule_path_elements(MapRules._value_rules_suffix)
            map_ctx.add_errors(key_ctx)
            if map_ctx.has_errors():
                map_ctx.add_field_path_element(_map_key_element(self._field, k))
                ctx.add_errors(map_ctx)


class OneofRules(Rules):
    """Rules for a oneof definition."""

    required = True

    def __init__(self, oneof: DescOneof, rules: validate_pb.OneofRules):
        self._oneof = oneof
        if not rules.required:
            self.required = False

    def validate(self, ctx: RuleContext, message: Message):
        if getattr(message, self._oneof.local_name) is None:
            if self.required:
                ctx.add(
                    Violation(
                        field=validate_pb.FieldPath(elements=[_oneof_to_element(self._oneof)]),
                        rule_id="required",
                        message="exactly one field is required in oneof",
                    )
                )
            return


def _message_child(field: _Field) -> DescMessage | None:
    if field.is_map:
        return field.value_field.message if field.value_field is not None else None
    if field.is_repeated:
        return field.item_field.message if field.item_field is not None else None
    return field.message


class RuleFactory:
    """Factory for creating and caching rules, keyed on protobuf-py descriptors."""

    _env: celpy.Environment
    _funcs: dict[str, celpy.CELFunction]

    def __init__(self, funcs: dict[str, celpy.CELFunction], registry: Registry | None = None):
        self._env = celpy.Environment(runner_class=InterpretedRunner)
        self._funcs = funcs
        self._registry = registry
        self._cache: dict[str, list[Rules] | Exception] = {}

    def get(self, desc: DescMessage) -> list[Rules]:
        key = desc.type_name
        if key not in self._cache:
            try:
                self._cache[key] = self._new_rules(desc)
            except Exception as e:
                self._cache[key] = e
        result = self._cache[key]
        if isinstance(result, Exception):
            raise result
        return result

    def _new_message_rule(self, rules: validate_pb.MessageRules, desc: DescMessage) -> MessageRules:
        result = MessageRules(rules, desc)
        for oneof in rules.oneof:
            result.add_oneof(oneof)
        for expr in rules.cel_expression:
            result.add_rule(self._env, self._funcs, expr)
        for cel in rules.cel:
            result.add_rule(self._env, self._funcs, cel)
        return result

    def _new_scalar_field_rule(
        self,
        field: _Field,
        field_level: validate_pb.FieldRules,
        *,
        for_items: bool = False,
        force_ignore_empty: bool = False,
    ):
        if field_level.ignore == validate_pb.Ignore.ALWAYS:
            return None
        type_case = _which_type(field_level)
        kw = {"for_items": for_items, "force_ignore_empty": force_ignore_empty, "registry": self._registry}
        checks: dict[str, tuple[int, str | None]] = {
            "duration": (0, "google.protobuf.Duration"),
            "field_mask": (0, "google.protobuf.FieldMask"),
            "timestamp": (0, "google.protobuf.Timestamp"),
            "bool": (8, "google.protobuf.BoolValue"),
            "bytes": (12, "google.protobuf.BytesValue"),
            "fixed32": (7, None),
            "fixed64": (6, None),
            "float": (2, "google.protobuf.FloatValue"),
            "double": (1, "google.protobuf.DoubleValue"),
            "int32": (5, "google.protobuf.Int32Value"),
            "int64": (3, "google.protobuf.Int64Value"),
            "sfixed32": (15, None),
            "sfixed64": (16, None),
            "sint32": (17, None),
            "sint64": (18, None),
            "uint32": (13, "google.protobuf.UInt32Value"),
            "uint64": (4, "google.protobuf.UInt64Value"),
            "string": (9, "google.protobuf.StringValue"),
        }
        if type_case is None:
            return FieldRules(self._env, self._funcs, field, field_level, **kw)
        if type_case == "enum":
            check_field_type(field, _TYPE_ENUM)
            return EnumRules(self._env, self._funcs, field, field_level, **kw)
        if type_case == "any":
            check_field_type(field, 0, "google.protobuf.Any")
            return AnyRules(self._env, self._funcs, field, field_level, registry=self._registry)
        if type_case in checks:
            expected, wrapper = checks[type_case]
            check_field_type(field, expected, wrapper)
            return FieldRules(self._env, self._funcs, field, field_level, **kw)
        msg = f"unknown rule type {type_case!r}"
        raise CompilationError(msg)

    def _new_field_rule(
        self, field: _Field, rules: validate_pb.FieldRules, *, force_ignore_empty: bool = False
    ) -> FieldRules:
        if not field.is_repeated:
            return self._new_scalar_field_rule(field, rules, force_ignore_empty=force_ignore_empty)
        type_oneof = rules.type
        if field.is_map:
            map_rules = type_oneof.value if type_oneof is not None and type_oneof.field == "map" else None
            key_field, value_field = field.key_field, field.value_field
            assert key_field is not None and value_field is not None  # noqa: S101
            key_rules = None
            value_rules = None
            if map_rules is not None and map_rules.keys is not None:
                key_rules = self._new_scalar_field_rule(key_field, map_rules.keys, for_items=True)
            if map_rules is not None and map_rules.values is not None:
                value_rules = self._new_scalar_field_rule(value_field, map_rules.values, for_items=True)
            return MapRules(self._env, self._funcs, field, rules, key_rules, value_rules, registry=self._registry)
        item_field = field.item_field
        assert item_field is not None  # noqa: S101
        item_rule = None
        rep_rules = type_oneof.value if type_oneof is not None and type_oneof.field == "repeated" else None
        if rep_rules is not None and rep_rules.items is not None:
            item_rule = self._new_scalar_field_rule(item_field, rep_rules.items)
        return RepeatedRules(self._env, self._funcs, field, rules, item_rule, registry=self._registry)

    def _new_rules(self, desc: DescMessage) -> list[Rules]:
        result: list[Rules] = []
        all_msg_oneof_fields: set[str] = set()

        msg_opts = desc.proto.options
        if msg_opts is not None and validate_pb.ext_message in msg_opts:
            message_level: validate_pb.MessageRules = msg_opts[validate_pb.ext_message]
            for oneof in message_level.oneof:
                all_msg_oneof_fields.update(oneof.fields)
            if rule := self._new_message_rule(message_level, desc):
                result.append(rule)

        for oneof in desc.oneofs:
            oneof_opts = oneof.proto.options
            if oneof_opts is not None and validate_pb.ext_oneof in oneof_opts:
                result.append(OneofRules(oneof, oneof_opts[validate_pb.ext_oneof]))

        ignore_field = _spec_field(validate_pb.FieldRules, "ignore")
        for field_desc in desc.fields:
            field = _Field.of(field_desc)
            field_opts = field_desc.proto.options
            field_level: validate_pb.FieldRules | None = None
            if field_opts is not None and validate_pb.ext_field in field_opts:
                field_level = field_opts[validate_pb.ext_field]
            if field_level is not None:
                force_ignore_empty = ignore_field not in field_level and field_desc.name in all_msg_oneof_fields
                if field_level.ignore == validate_pb.Ignore.ALWAYS:
                    continue
                result.append(self._new_field_rule(field, field_level, force_ignore_empty=force_ignore_empty))
                type_oneof = field_level.type
                if type_oneof is not None and type_oneof.field == "repeated":
                    rep = type_oneof.value
                    if rep.items is not None and rep.items.ignore == validate_pb.Ignore.ALWAYS:
                        continue
            sub_desc = _message_child(field)
            if sub_desc is None:
                continue
            if field.is_map:
                result.append(MapValMsgRule(self, field, sub_desc))
            elif field.is_repeated:
                result.append(RepeatedMsgRule(self, field, sub_desc))
            else:
                result.append(SubMsgRule(self, field, sub_desc))
        return result


class SubMsgRule(Rules):
    def __init__(self, factory: RuleFactory, field: _Field, sub_desc: DescMessage):
        self._factory = factory
        self._field = field
        self._sub_desc = sub_desc

    def validate(self, ctx: RuleContext, message: Message):
        if not self._field.is_present(message):
            return
        rules = self._factory.get(self._sub_desc)
        if not rules:
            return
        val = self._field.get(message)
        sub_ctx = ctx.sub_context()
        for rule in rules:
            rule.validate(sub_ctx, val)
        if sub_ctx.has_errors():
            sub_ctx.add_field_path_element(_field_to_element(self._field))
            ctx.add_errors(sub_ctx)


class MapValMsgRule(Rules):
    def __init__(self, factory: RuleFactory, field: _Field, sub_desc: DescMessage):
        self._factory = factory
        self._field = field
        self._sub_desc = sub_desc

    def validate(self, ctx: RuleContext, message: Message):
        val = self._field.get(message)
        if not val:
            return
        rules = self._factory.get(self._sub_desc)
        if not rules:
            return
        for k, v in val.items():
            sub_ctx = ctx.sub_context()
            for rule in rules:
                rule.validate(sub_ctx, v)
            if sub_ctx.has_errors():
                sub_ctx.add_field_path_element(_map_key_element(self._field, k))
                ctx.add_errors(sub_ctx)


class RepeatedMsgRule(Rules):
    def __init__(self, factory: RuleFactory, field: _Field, sub_desc: DescMessage):
        self._factory = factory
        self._field = field
        self._sub_desc = sub_desc

    def validate(self, ctx: RuleContext, message: Message):
        val = self._field.get(message)
        if not val:
            return
        rules = self._factory.get(self._sub_desc)
        if not rules:
            return
        for idx, item in enumerate(val):
            sub_ctx = ctx.sub_context()
            for rule in rules:
                rule.validate(sub_ctx, item)
            if sub_ctx.has_errors():
                sub_ctx.add_field_path_element(_indexed_field_element(self._field, idx))
                ctx.add_errors(sub_ctx)
