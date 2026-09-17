// Copyright (c) 2023-2026 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The bool, enum, bytes, repeated, map and field mask rules.

use super::{Native, regex};
use crate::Error;
use crate::rules::standard::format::{Hex, List, Text};
use crate::rules::standard::{BytesTest, Cmp, FieldMaskTest, ListTest, MapTest, Test};
use crate::validate::__buffa::oneof;
use crate::validate::{BoolRules, BytesRules, EnumRules, FieldMaskRules, MapRules, RepeatedRules};

pub(super) fn bool_check(prefix: &str, r: &BoolRules, number: u32) -> Option<Native> {
    match number {
        1 => r
            .r#const
            .map(|c| Native::new(prefix, "const", format!("must equal {c}"), Test::Bool(c))),
        _ => None,
    }
}

pub(super) fn enum_check(prefix: &str, r: &EnumRules, number: u32) -> Option<Native> {
    let ints = |list: &[i32]| list.iter().map(|&v| i64::from(v)).collect::<Vec<_>>();
    match number {
        1 => r.r#const.map(|c| {
            Native::new(
                prefix,
                "const",
                format!("must equal {c}"),
                Test::Int(Cmp::Const(i64::from(c))),
            )
        }),
        3 => {
            let list = ints(&r.r#in);
            Some(Native::new(
                prefix,
                "in",
                format!("must be in list {}", List(&list)),
                Test::Int(Cmp::In(list)),
            ))
        }
        4 => {
            let list = ints(&r.not_in);
            Some(Native::new(
                prefix,
                "not_in",
                format!("must not be in list {}", List(&list)),
                Test::Int(Cmp::NotIn(list)),
            ))
        }
        _ => None,
    }
}

pub(super) fn bytes_checks(
    prefix: &str,
    r: &BytesRules,
    number: u32,
) -> Result<Vec<Native>, Error> {
    let bytes_check = |suffix: &str, message: String, test: BytesTest| {
        Ok(vec![Native::new(
            prefix,
            suffix,
            message,
            Test::Bytes(test),
        )])
    };
    match number {
        1 => {
            let c = r.r#const.clone().unwrap_or_default();
            bytes_check("const", format!("must be {}", Hex(&c)), BytesTest::Const(c))
        }
        2 => {
            let n = r.min_len.unwrap_or_default();
            bytes_check(
                "min_len",
                format!("must be at least {n} bytes"),
                BytesTest::MinLen(n),
            )
        }
        3 => {
            let n = r.max_len.unwrap_or_default();
            bytes_check(
                "max_len",
                format!("must be at most {n} bytes"),
                BytesTest::MaxLen(n),
            )
        }
        4 => {
            let p = r.pattern.clone().unwrap_or_default();
            let compiled = regex(&p)?;
            bytes_check(
                "pattern",
                format!("must match regex pattern `{p}`"),
                BytesTest::Pattern(compiled),
            )
        }
        5 => {
            let p = r.prefix.clone().unwrap_or_default();
            bytes_check(
                "prefix",
                format!("does not have prefix {}", Hex(&p)),
                BytesTest::Prefix(p),
            )
        }
        6 => {
            let p = r.suffix.clone().unwrap_or_default();
            bytes_check(
                "suffix",
                format!("does not have suffix {}", Hex(&p)),
                BytesTest::Suffix(p),
            )
        }
        7 => {
            let p = r.contains.clone().unwrap_or_default();
            bytes_check(
                "contains",
                format!("does not contain {}", Hex(&p)),
                BytesTest::Contains(p),
            )
        }
        8 => bytes_check(
            "in",
            format!(
                "must be in list {}",
                List(r.r#in.iter().map(|bytes| Text(bytes)))
            ),
            BytesTest::In(r.r#in.clone()),
        ),
        9 => bytes_check(
            "not_in",
            format!(
                "must not be in list {}",
                List(r.not_in.iter().map(|bytes| Text(bytes)))
            ),
            BytesTest::NotIn(r.not_in.clone()),
        ),
        13 => {
            let n = r.len.unwrap_or_default();
            bytes_check("len", format!("must be {n} bytes"), BytesTest::Len(n))
        }
        _ => Ok(bytes_format_checks(prefix, r, number)),
    }
}

/// The checks of a bytes format rule, which go by length alone.
fn bytes_format_checks(prefix: &str, r: &BytesRules, number: u32) -> Vec<Native> {
    use oneof::bytes_rules::WellKnown as Wk;
    let (suffix, what, test) = match &r.well_known {
        Some(Wk::Ip(true)) if number == 10 => ("ip", "IP address", BytesTest::Ip),
        Some(Wk::Ipv4(true)) if number == 11 => ("ipv4", "IPv4 address", BytesTest::Ipv4),
        Some(Wk::Ipv6(true)) if number == 12 => ("ipv6", "IPv6 address", BytesTest::Ipv6),
        Some(Wk::Uuid(true)) if number == 15 => ("uuid", "UUID", BytesTest::Uuid),
        _ => return Vec::new(),
    };
    vec![
        Native::new(
            prefix,
            suffix,
            format!("must be a valid {what}"),
            Test::Bytes(test),
        ),
        Native::new(
            prefix,
            &format!("{suffix}_empty"),
            format!("value is empty, which is not a valid {what}"),
            Test::Bytes(BytesTest::Empty),
        ),
    ]
}

pub(super) fn repeated_check(prefix: &str, r: &RepeatedRules, number: u32) -> Option<Native> {
    match number {
        1 => {
            let n = r.min_items.unwrap_or_default();
            Some(Native::new(
                prefix,
                "min_items",
                format!("must contain at least {n} item(s)"),
                Test::List(ListTest::MinItems(n)),
            ))
        }
        2 => {
            let n = r.max_items.unwrap_or_default();
            Some(Native::new(
                prefix,
                "max_items",
                format!("must contain no more than {n} item(s)"),
                Test::List(ListTest::MaxItems(n)),
            ))
        }
        3 if r.unique == Some(true) => Some(Native::new(
            prefix,
            "unique",
            "repeated value must contain unique items",
            Test::List(ListTest::Unique),
        )),
        _ => None,
    }
}

pub(super) fn map_check(prefix: &str, r: &MapRules, number: u32) -> Option<Native> {
    match number {
        1 => {
            let n = r.min_pairs.unwrap_or_default();
            Some(Native::new(
                prefix,
                "min_pairs",
                format!("map must be at least {n} entries"),
                Test::Map(MapTest::MinPairs(n)),
            ))
        }
        2 => {
            let n = r.max_pairs.unwrap_or_default();
            Some(Native::new(
                prefix,
                "max_pairs",
                format!("map must be at most {n} entries"),
                Test::Map(MapTest::MaxPairs(n)),
            ))
        }
        _ => None,
    }
}

pub(super) fn field_mask_check(prefix: &str, r: &FieldMaskRules, number: u32) -> Option<Native> {
    match number {
        1 => r.r#const.as_option().map(|c| {
            Native::new(
                prefix,
                "const",
                format!("must equal paths {}", List(&c.paths)),
                Test::FieldMask(FieldMaskTest::Const(c.paths.clone())),
            )
        }),
        2 => Some(Native::new(
            prefix,
            "in",
            format!("must only contain paths in {}", List(&r.r#in)),
            Test::FieldMask(FieldMaskTest::In(r.r#in.clone())),
        )),
        3 => Some(Native::new(
            prefix,
            "not_in",
            format!("must not contain any paths in {}", List(&r.not_in)),
            Test::FieldMask(FieldMaskTest::NotIn(r.not_in.clone())),
        )),
        _ => None,
    }
}
