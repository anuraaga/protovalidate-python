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

import math
import re
from decimal import Decimal

import celpy
from celpy import celtypes

_TYPE_NAMES: dict[type, str] = {
    type(None): "null_type",
    celtypes.BoolType: "bool",
    celtypes.BytesType: "bytes",
    celtypes.DoubleType: "double",
    celtypes.DurationType: "google.protobuf.Duration",
    celtypes.IntType: "int",
    celtypes.ListType: "list",
    celtypes.MapType: "map",
    celtypes.StringType: "string",
    celtypes.TimestampType: "google.protobuf.Timestamp",
    celtypes.UintType: "uint",
}


class StringFormat:
    """An implementation of string.format() in CEL."""

    def __init__(self):
        self.fmt = None

    def format(self, fmt: celtypes.Value, args: celtypes.Value) -> celpy.Result:
        if not isinstance(fmt, celtypes.StringType):
            return celpy.CELEvalError("format() requires a string as the first argument")
        if not isinstance(args, celtypes.ListType):
            return celpy.CELEvalError("format() requires a list as the second argument")
        # printf style formatting
        i = 0
        j = 0
        result = ""
        while i < len(fmt):
            if fmt[i] != "%":
                result += fmt[i]
                i += 1
                continue

            if i + 1 < len(fmt) and fmt[i + 1] == "%":
                result += "%"
                i += 2
                continue
            if j >= len(args):
                return celpy.CELEvalError(f"index {j} out of range")
            arg = args[j]
            j += 1
            i += 1
            if i >= len(fmt):
                return celpy.CELEvalError("format() incomplete format specifier")
            precision = 6
            if fmt[i] == ".":
                i += 1
                precision = 0
                while i < len(fmt) and fmt[i].isdigit():
                    precision = precision * 10 + int(fmt[i])
                    i += 1
            if i >= len(fmt):
                return celpy.CELEvalError("format() incomplete format specifier")
            match fmt[i]:
                case "f":
                    result += self.__format_float(arg, precision)
                case "e":
                    result += self.__format_exponential(arg, precision)
                case "d":
                    result += self.__format_int(arg)
                case "s":
                    result += self.__format_string(arg)
                case "x":
                    result += self.__format_hex(arg)
                case "X":
                    result += self.__format_hex(arg).upper()
                case "o":
                    result += self.__format_oct(arg)
                case "b":
                    result += self.__format_bin(arg)
                case _:
                    return celpy.CELEvalError(
                        f'could not parse formatting clause: unrecognized formatting clause "{fmt[i]}"'
                    )
            i += 1
        if j < len(args):
            return celpy.CELEvalError("format() too many arguments for format string")

        return celtypes.StringType(result)

    def __validate_number(self, arg: celtypes.DoubleType | celtypes.IntType | celtypes.UintType) -> str | None:
        if math.isnan(arg):
            return "NaN"
        if math.isinf(arg):
            if arg < 0:
                return "-Infinity"
            return "Infinity"
        return None

    def __format_float(self, arg: celtypes.Value, precision: int) -> str:
        if isinstance(arg, celtypes.DoubleType):
            result = self.__validate_number(arg)
            if result is not None:
                return result
            return f"{arg:.{precision}f}"
        msg = (
            "error during formatting: fixed-point clause can only be used on doubles, was given "
            f"{self.__type_str(type(arg))}"
        )
        raise celpy.CELEvalError(msg)

    def __format_exponential(self, arg: celtypes.Value, precision: int) -> str:
        if isinstance(arg, celtypes.DoubleType):
            result = self.__validate_number(arg)
            if result is not None:
                return result
            return f"{arg:.{precision}e}"
        msg = (
            "error during formatting: scientific clause can only be used on doubles, was given "
            f"{self.__type_str(type(arg))}"
        )
        raise celpy.CELEvalError(msg)

    def __format_int(self, arg: celtypes.Value) -> str:
        if isinstance(arg, celtypes.IntType | celtypes.UintType | celtypes.DoubleType):
            result = self.__validate_number(arg)
            if result is not None:
                return result
            return f"{arg}"
        msg = (
            "error during formatting: decimal clause can only be used on integers, was given "
            f"{self.__type_str(type(arg))}"
        )
        raise celpy.CELEvalError(msg)

    def __format_hex(self, arg: celtypes.Value) -> str:
        match arg:
            case celtypes.IntType() | celtypes.UintType():
                return f"{arg:x}"
            case celtypes.BytesType():
                return arg.hex()
            case celtypes.StringType():
                return arg.encode("utf-8").hex()
            case _:
                msg = (
                    "error during formatting: only integers, byte buffers, and strings can be formatted as hex, "
                    f"was given {self.__type_str(type(arg))}"
                )
                raise celpy.CELEvalError(msg)

    def __format_oct(self, arg: celtypes.Value) -> str:
        if isinstance(arg, celtypes.IntType | celtypes.UintType):
            return f"{arg:o}"
        msg = (
            "error during formatting: octal clause can only be used on integers, was given "
            f"{self.__type_str(type(arg))}"
        )
        raise celpy.CELEvalError(msg)

    def __format_bin(self, arg: celtypes.Value) -> str:
        if isinstance(arg, celtypes.IntType | celtypes.UintType | celtypes.BoolType):
            return f"{arg:b}"
        msg = (
            "error during formatting: only integers and bools can be formatted as binary, was given "
            f"{self.__type_str(type(arg))}"
        )
        raise celpy.CELEvalError(msg)

    def __format_string(self, arg: celtypes.Value) -> str:
        match arg:
            case None:
                return "null"
            case type():
                return self.__type_str(arg)
            case celtypes.BoolType():
                # True -> true
                return str(arg).lower()
            case celtypes.BytesType():
                decoded = arg.decode("utf-8", errors="replace")
                # Collapse any contiguous placeholders into one
                return re.sub("\\ufffd+", "\ufffd", decoded)
            case celtypes.DoubleType():
                result = self.__validate_number(arg)
                if result is not None:
                    return result
                return f"{arg:g}"
            case celtypes.DurationType():
                return self.__format_duration(arg)
            case celtypes.IntType() | celtypes.UintType():
                result = self.__validate_number(arg)
                if result is not None:
                    return result
                return f"{arg}"
            case celtypes.ListType():
                return self.__format_list(arg)
            case celtypes.MapType():
                return self.__format_map(arg)
            case celtypes.StringType():
                return arg
            case celtypes.TimestampType():
                base = arg.isoformat()
                if arg.getMilliseconds() != 0:
                    base = arg.isoformat(timespec="milliseconds")
                return base.removesuffix("+00:00") + "Z"
            case _:
                return "unknown"

    def __format_list(self, arg: celtypes.ListType) -> str:
        return "[" + ", ".join(self.__format_string(val) for val in arg) + "]"

    def __format_map(self, arg: celtypes.MapType) -> str:
        m = {self.__format_string(cel_key): self.__format_string(cel_val) for cel_key, cel_val in arg.items()}
        return "{" + ", ".join(key + ": " + val for key, val in sorted(m.items())) + "}"

    def __format_duration(self, arg: celtypes.DurationType) -> str:
        return f"{arg.seconds + Decimal(arg.microseconds) / Decimal(1_000_000):f}s"

    def __type_str(self, arg: celtypes.Type) -> str:
        return _TYPE_NAMES.get(arg, "unknown")
