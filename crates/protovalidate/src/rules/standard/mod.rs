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

//! The standard rules, evaluated natively.
//!
//! `validate.proto` defines every standard rule as a CEL expression over
//! `this` and `rules`, with a message built from the rule's value. A
//! [`Check`] is one such expression compiled ahead of time: the rules
//! message is known when the field's rules are built, so the message is
//! formatted then and only the [`Test`] against the value remains. Checks
//! report the same rule ids, messages and rule paths the CEL expressions
//! do, and run in the same order.

pub(crate) mod build;
mod format;
pub(crate) mod wellknown;

use std::collections::HashSet;
use std::time::SystemTime;

use regex::Regex;

use crate::descriptors::wkt;
use crate::protobuf::{List as _, Map as _, Message as _, Runtime, Val};
use crate::validate::FieldPathElement;
pub(crate) use format::{Duration, Timestamp};

/// One standard rule against one value.
pub(crate) struct Check {
    /// The rule id, `int32.gt_lt` say.
    pub id: String,
    pub message: String,
    /// The rule path, leaf first: `[Int32Rules.gt, FieldRules.int32]`.
    pub rule_path: [FieldPathElement; 2],
    pub test: Test,
}

/// What a check tests the value for.
pub(crate) enum Test {
    Int(Cmp<i64>),
    Uint(Cmp<u64>),
    Double(Cmp<f64>),
    /// `float.finite` and `double.finite`.
    Finite,
    /// `bool.const`.
    Bool(bool),
    Str(StrTest),
    Bytes(BytesTest),
    List(ListTest),
    Map(MapTest),
    Duration(Cmp<Duration>),
    Timestamp(Cmp<Timestamp>),
    Now(NowTest),
    FieldMask(FieldMaskTest),
}

/// A comparison with the rule's values: the numeric, duration and timestamp
/// rules. The range variants are the combinations `validate.proto` spells
/// out on the `gt` and `gte` rules when a `lt` or `lte` is also set.
pub(crate) enum Cmp<T> {
    Const(T),
    Lt(T),
    Lte(T),
    Gt(T),
    Gte(T),
    /// `gt < lt`: the value must be strictly inside.
    GtLt {
        gt: T,
        lt: T,
    },
    /// `lt < gt`: the value must be strictly outside `lt..=gt`.
    GtLtExclusive {
        gt: T,
        lt: T,
    },
    GtLte {
        gt: T,
        lte: T,
    },
    GtLteExclusive {
        gt: T,
        lte: T,
    },
    GteLt {
        gte: T,
        lt: T,
    },
    GteLtExclusive {
        gte: T,
        lt: T,
    },
    GteLte {
        gte: T,
        lte: T,
    },
    GteLteExclusive {
        gte: T,
        lte: T,
    },
    In(Vec<T>),
    NotIn(Vec<T>),
}

/// Values for which every comparison rule fails: NaN.
pub(crate) trait MaybeNan {
    fn is_nan(&self) -> bool {
        false
    }
}

impl MaybeNan for i64 {}
impl MaybeNan for u64 {}
impl MaybeNan for Duration {}
impl MaybeNan for Timestamp {}
impl MaybeNan for f64 {
    fn is_nan(&self) -> bool {
        f64::is_nan(*self)
    }
}

impl<T: PartialOrd + MaybeNan> Cmp<T> {
    /// Whether `value` breaks the rule.
    fn fails(&self, value: &T) -> bool {
        if value.is_nan() {
            // NaN is not equal to, in, or ordered against anything: every
            // rule fails except `not_in`, which it trivially satisfies.
            return !matches!(self, Self::NotIn(_));
        }
        match self {
            Self::Const(c) => value != c,
            Self::Lt(lt) => value >= lt,
            Self::Lte(lte) => value > lte,
            Self::Gt(gt) => value <= gt,
            Self::Gte(gte) => value < gte,
            Self::GtLt { gt, lt } => value >= lt || value <= gt,
            Self::GtLtExclusive { gt, lt } => lt <= value && value <= gt,
            Self::GtLte { gt, lte } => value > lte || value <= gt,
            Self::GtLteExclusive { gt, lte } => lte < value && value <= gt,
            Self::GteLt { gte, lt } => value >= lt || value < gte,
            Self::GteLtExclusive { gte, lt } => lt <= value && value < gte,
            Self::GteLte { gte, lte } => value > lte || value < gte,
            Self::GteLteExclusive { gte, lte } => lte < value && value < gte,
            Self::In(list) => !list.contains(value),
            Self::NotIn(list) => list.contains(value),
        }
    }
}

pub(crate) enum StrTest {
    Const(String),
    /// In Unicode code points, as CEL's `size()`.
    Len(u64),
    MinLen(u64),
    MaxLen(u64),
    LenBytes(u64),
    MinBytes(u64),
    MaxBytes(u64),
    Pattern(Regex),
    Prefix(String),
    Suffix(String),
    Contains(String),
    NotContains(String),
    In(Vec<String>),
    NotIn(Vec<String>),
    WellKnown(WellKnown),
    /// The `_empty` companion of a well-known format: the format rule lets
    /// an empty string through, and this one reports it.
    Empty,
}

/// A well-known string format.
pub(crate) enum WellKnown {
    Email,
    Hostname,
    Ip,
    Ipv4,
    Ipv6,
    Uri,
    UriRef,
    Address,
    Uuid,
    Tuuid,
    IpWithPrefixlen,
    Ipv4WithPrefixlen,
    Ipv6WithPrefixlen,
    IpPrefix,
    Ipv4Prefix,
    Ipv6Prefix,
    HostAndPort,
    Ulid,
    ProtobufFqn,
    ProtobufDotFqn,
    HeaderName { strict: bool },
    HeaderValue { strict: bool },
}

impl WellKnown {
    fn fails(&self, s: &str) -> bool {
        // Most formats let an empty string through, leaving it to the
        // `_empty` companion; a URI reference and a header value do not.
        match self {
            Self::UriRef => return !wellknown::is_uri_ref(s),
            Self::HeaderValue { strict } => return !wellknown::is_header_value(s, *strict),
            _ if s.is_empty() => return false,
            _ => {}
        }
        !match self {
            Self::Email => wellknown::is_email(s),
            Self::Hostname => wellknown::is_hostname(s),
            Self::Ip => wellknown::is_ip(s),
            Self::Ipv4 => wellknown::is_ipv4(s),
            Self::Ipv6 => wellknown::is_ipv6(s),
            Self::Uri => wellknown::is_uri(s),
            Self::Address => wellknown::is_hostname(s) || wellknown::is_ip(s),
            Self::Uuid => wellknown::is_uuid(s),
            Self::Tuuid => wellknown::is_tuuid(s),
            Self::IpWithPrefixlen => wellknown::is_ip_prefix(s, false),
            Self::Ipv4WithPrefixlen => wellknown::is_ipv4_prefix(s, false),
            Self::Ipv6WithPrefixlen => wellknown::is_ipv6_prefix(s, false),
            Self::IpPrefix => wellknown::is_ip_prefix(s, true),
            Self::Ipv4Prefix => wellknown::is_ipv4_prefix(s, true),
            Self::Ipv6Prefix => wellknown::is_ipv6_prefix(s, true),
            Self::HostAndPort => wellknown::is_host_and_port(s, true),
            Self::Ulid => wellknown::is_ulid(s),
            Self::ProtobufFqn => wellknown::is_protobuf_fqn(s),
            Self::ProtobufDotFqn => wellknown::is_protobuf_dot_fqn(s),
            Self::HeaderName { strict } => wellknown::is_header_name(s, *strict),
            Self::UriRef | Self::HeaderValue { .. } => unreachable!("handled above"),
        }
    }
}

impl StrTest {
    fn fails(&self, s: &str) -> bool {
        match self {
            Self::Const(c) => s != c,
            Self::Len(n) => chars(s) != *n,
            Self::MinLen(n) => chars(s) < *n,
            Self::MaxLen(n) => chars(s) > *n,
            Self::LenBytes(n) => s.len() as u64 != *n,
            Self::MinBytes(n) => (s.len() as u64) < *n,
            Self::MaxBytes(n) => s.len() as u64 > *n,
            Self::Pattern(regex) => !regex.is_match(s),
            Self::Prefix(p) => !s.starts_with(p.as_str()),
            Self::Suffix(p) => !s.ends_with(p.as_str()),
            Self::Contains(p) => !s.contains(p.as_str()),
            Self::NotContains(p) => s.contains(p.as_str()),
            Self::In(list) => !list.iter().any(|item| item == s),
            Self::NotIn(list) => list.iter().any(|item| item == s),
            Self::WellKnown(format) => format.fails(s),
            Self::Empty => s.is_empty(),
        }
    }
}

fn chars(s: &str) -> u64 {
    s.chars().count() as u64
}

pub(crate) enum BytesTest {
    Const(Vec<u8>),
    Len(u64),
    MinLen(u64),
    MaxLen(u64),
    /// Matched against the bytes read as UTF-8, as CEL's `string(this)`.
    Pattern(Regex),
    Prefix(Vec<u8>),
    Suffix(Vec<u8>),
    Contains(Vec<u8>),
    In(Vec<Vec<u8>>),
    NotIn(Vec<Vec<u8>>),
    /// 4 or 16 bytes, or none.
    Ip,
    Ipv4,
    Ipv6,
    /// 16 bytes, or none.
    Uuid,
    /// The `_empty` companion of the formats above.
    Empty,
}

impl BytesTest {
    /// `Err` when the value cannot be checked: bytes that are not UTF-8
    /// cannot be matched against a pattern, as CEL's `string()` fails on
    /// them.
    fn fails(&self, b: &[u8]) -> Result<bool, String> {
        Ok(match self {
            Self::Const(c) => b != c.as_slice(),
            Self::Len(n) => b.len() as u64 != *n,
            Self::MinLen(n) => (b.len() as u64) < *n,
            Self::MaxLen(n) => b.len() as u64 > *n,
            Self::Pattern(regex) => match std::str::from_utf8(b) {
                Ok(s) => !regex.is_match(s),
                Err(_) => return Err("value must be valid UTF-8 to apply regexp".to_owned()),
            },
            Self::Prefix(p) => !b.starts_with(p),
            Self::Suffix(p) => !b.ends_with(p),
            Self::Contains(p) => !contains(b, p),
            Self::In(list) => !list.iter().any(|item| item == b),
            Self::NotIn(list) => list.iter().any(|item| item == b),
            Self::Ip => !matches!(b.len(), 0 | 4 | 16),
            Self::Ipv4 => !matches!(b.len(), 0 | 4),
            Self::Ipv6 => !matches!(b.len(), 0 | 16),
            Self::Uuid => !matches!(b.len(), 0 | 16),
            Self::Empty => b.is_empty(),
        })
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

pub(crate) enum ListTest {
    MinItems(u64),
    MaxItems(u64),
    Unique,
}

pub(crate) enum MapTest {
    MinPairs(u64),
    MaxPairs(u64),
}

/// The timestamp rules relative to the time of validation.
pub(crate) enum NowTest {
    LtNow,
    GtNow,
    Within(Duration),
}

impl NowTest {
    fn fails(&self, value: Timestamp) -> bool {
        let now = now();
        match self {
            Self::LtNow => value > now,
            Self::GtNow => value < now,
            Self::Within(within) => value.0 < now.0 - within.0 || value.0 > now.0 + within.0,
        }
    }
}

fn now() -> Timestamp {
    let nanos = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => i128::try_from(since.as_nanos()).unwrap_or(i128::MAX),
        Err(before) => -i128::try_from(before.duration().as_nanos()).unwrap_or(i128::MAX),
    };
    Timestamp(nanos)
}

pub(crate) enum FieldMaskTest {
    Const(Vec<String>),
    /// Every path must be in the list, or below a path in it.
    In(Vec<String>),
    NotIn(Vec<String>),
}

fn covered(paths: &[String], path: &str) -> bool {
    paths.iter().any(|allowed| {
        allowed == path
            || path
                .strip_prefix(allowed.as_str())
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

impl FieldMaskTest {
    fn fails(&self, paths: &[String]) -> bool {
        match self {
            Self::Const(c) => paths != c.as_slice(),
            Self::In(list) => !paths.iter().all(|path| covered(list, path)),
            Self::NotIn(list) => paths.iter().any(|path| covered(list, path)),
        }
    }
}

/// A list element as `unique()` compares it: by type and value, with
/// signed zeros equal and NaN never equal to anything.
#[derive(PartialEq, Eq, Hash)]
pub(crate) enum UniqueKey<'a> {
    Bool(bool),
    Int(i64),
    Uint(u64),
    Double(u64),
    Str(&'a str),
    Bytes(&'a [u8]),
}

impl UniqueKey<'_> {
    /// The key of a double; `None` for NaN, which duplicates nothing.
    pub(crate) fn double(value: f64) -> Option<Self> {
        if value.is_nan() {
            return None;
        }
        Some(Self::Double(if value == 0.0 { 0 } else { value.to_bits() }))
    }
}

fn unique_key<'a, R: Runtime>(value: &'a Val<'_, R>) -> Option<UniqueKey<'a>> {
    match value {
        Val::Bool(b) => Some(UniqueKey::Bool(*b)),
        Val::Int(i) => Some(UniqueKey::Int(*i)),
        Val::Enum(e) => Some(UniqueKey::Int(i64::from(*e))),
        Val::Uint(u) => Some(UniqueKey::Uint(*u)),
        Val::Double(f) => UniqueKey::double(*f),
        Val::String(s) => Some(UniqueKey::Str(s)),
        Val::Bytes(b) => Some(UniqueKey::Bytes(b)),
        Val::Message(_) | Val::List(_) | Val::Map(_) => None,
    }
}

/// Whether any key occurs twice; elements without a key never do.
pub(crate) fn has_duplicates<'a>(keys: impl IntoIterator<Item = Option<UniqueKey<'a>>>) -> bool {
    let mut seen = HashSet::new();
    keys.into_iter().flatten().any(|key| !seen.insert(key))
}

fn list_has_duplicates<R: Runtime>(list: &R::List<'_>) -> bool {
    let items: Vec<Val<'_, R>> = (0..list.len()).filter_map(|i| list.get(i)).collect();
    has_duplicates(items.iter().map(unique_key))
}

/// The seconds and nanos of a `Duration` or `Timestamp` message, as one
/// count of nanoseconds; zero for a message that is not there.
fn nanos_of<R: Runtime>(value: Option<&Val<'_, R>>) -> i128 {
    let Some(Val::Message(message)) = value else {
        return 0;
    };
    let seconds = match message.get(&wkt::SECONDS) {
        Some(Val::Int(seconds)) => seconds,
        _ => 0,
    };
    let nanos = match message.get(&wkt::NANOS) {
        Some(Val::Int(nanos)) => nanos,
        _ => 0,
    };
    i128::from(seconds) * 1_000_000_000 + i128::from(nanos)
}

/// The `paths` of a `FieldMask` message.
fn paths_of<R: Runtime>(value: Option<&Val<'_, R>>) -> Vec<String> {
    let Some(Val::Message(message)) = value else {
        return Vec::new();
    };
    let Some(Val::List(list)) = message.get(&wkt::FIELD_MASK_PATHS) else {
        return Vec::new();
    };
    (0..list.len())
        .filter_map(|i| match list.get(i) {
            Some(Val::String(s)) => Some(s.into_owned()),
            _ => None,
        })
        .collect()
}

impl Test {
    /// Whether `value` breaks the rule, or why it could not be checked.
    /// `None` is a field the message does not have at all, which reads as
    /// the type's default.
    pub(crate) fn fails<R: Runtime>(&self, value: Option<&Val<'_, R>>) -> Result<bool, String> {
        Ok(match self {
            Self::Int(cmp) => cmp.fails(&match value {
                Some(Val::Int(i)) => *i,
                Some(Val::Enum(e)) => i64::from(*e),
                _ => 0,
            }),
            Self::Uint(cmp) => cmp.fails(&match value {
                Some(Val::Uint(u)) => *u,
                _ => 0,
            }),
            Self::Double(cmp) => cmp.fails(&double_of(value)),
            Self::Finite => !double_of(value).is_finite(),
            Self::Bool(c) => match value {
                Some(Val::Bool(b)) => b != c,
                _ => *c,
            },
            Self::Str(test) => test.fails(match value {
                Some(Val::String(s)) => s,
                _ => "",
            }),
            Self::Bytes(test) => test.fails(match value {
                Some(Val::Bytes(b)) => b,
                _ => &[],
            })?,
            Self::List(test) => {
                let Some(Val::List(list)) = value else {
                    return Ok(matches!(test, ListTest::MinItems(n) if *n > 0));
                };
                match test {
                    ListTest::MinItems(n) => (list.len() as u64) < *n,
                    ListTest::MaxItems(n) => list.len() as u64 > *n,
                    ListTest::Unique => list_has_duplicates::<R>(list),
                }
            }
            Self::Map(test) => {
                let len = match value {
                    Some(Val::Map(map)) => map.len() as u64,
                    _ => 0,
                };
                match test {
                    MapTest::MinPairs(n) => len < *n,
                    MapTest::MaxPairs(n) => len > *n,
                }
            }
            Self::Duration(cmp) => cmp.fails(&Duration(nanos_of(value))),
            Self::Timestamp(cmp) => cmp.fails(&Timestamp(nanos_of(value))),
            Self::Now(test) => test.fails(Timestamp(nanos_of(value))),
            Self::FieldMask(test) => test.fails(&paths_of(value)),
        })
    }
}

fn double_of<R: Runtime>(value: Option<&Val<'_, R>>) -> f64 {
    match value {
        Some(Val::Double(f)) => *f,
        _ => 0.0,
    }
}
