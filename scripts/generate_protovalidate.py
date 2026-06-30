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

import re
from pathlib import Path
from subprocess import run

_REPO = Path(__file__).parent.parent


def _module(name: str, version: str) -> str:
    if re.match(r"^v\d+\.\d+\.\d+(\-.+)?$", version):
        # Version tag, fetch from the BSR.
        return f"buf.build/bufbuild/{name}:{version}"
    # Not a tag, generally an unreleased commit, fetch directly from git.
    return f"https://github.com/bufbuild/protovalidate.git#subdir=proto/{name},ref={version}"


def main(version: str) -> None:
    # The relocatable buf.validate stub bundled into protovalidate itself, so
    # users do not add the protos. protobuf-py gencode only (no *_pb2.py); the
    # template writes into protovalidate/_gen.
    run(  # noqa: S603
        [  # noqa: S607
            "buf",
            "generate",
            _module("protovalidate", version),
            "--path",
            "buf/validate",
            "--template",
            str(_REPO / "buf.gen.bundle.yaml"),
        ],
        cwd=_REPO,
        check=True,
    )
    # The conformance harness (and the buf.validate it imports) for the test
    # suite, generated into test/gen alongside the example/bench protos using
    # test/buf.gen.yaml.
    run(  # noqa: S603
        [  # noqa: S607
            "buf",
            "generate",
            _module("protovalidate-testing", version),
            "--path",
            "buf/validate/conformance/harness",
            "--include-imports",
        ],
        cwd=_REPO / "test",
        check=True,
    )
