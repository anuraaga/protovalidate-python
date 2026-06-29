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

from cel_expr_python import cel
from google.protobuf import descriptor_pool

_env = cel.NewEnv(descriptor_pool=descriptor_pool.Default())


def test_function_matches_re2():
    # The runtime must evaluate matches() with RE2, which the protovalidate
    # spec requires. \z is valid RE2 syntax for end of text.
    result = _env.compile("''.matches('^\\\\z')").eval()
    assert result.plain_value() is True
    # \Z is invalid RE2 syntax, so evaluation must fail.
    result = _env.compile("''.matches('^\\\\Z')").eval()
    assert result.type() == cel.Type.ERROR
