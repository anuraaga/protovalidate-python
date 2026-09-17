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

//! The string rules.

use super::{Native, regex};
use crate::Error;
use crate::rules::standard::format::List;
use crate::rules::standard::{StrTest, Test, WellKnown};
use crate::validate::__buffa::oneof;
use crate::validate::{KnownRegex, StringRules};

/// Whether a well-known format rule set on field `number` is in force: the
/// booleans have to be true, and the regex rule has to be the one set.
fn well_known_enabled(rule: &oneof::string_rules::WellKnown, number: u32) -> bool {
    use oneof::string_rules::WellKnown as Wk;
    match rule {
        Wk::Email(b)
        | Wk::Hostname(b)
        | Wk::Ip(b)
        | Wk::Ipv4(b)
        | Wk::Ipv6(b)
        | Wk::Uri(b)
        | Wk::UriRef(b)
        | Wk::Address(b)
        | Wk::Uuid(b)
        | Wk::Tuuid(b)
        | Wk::IpWithPrefixlen(b)
        | Wk::Ipv4WithPrefixlen(b)
        | Wk::Ipv6WithPrefixlen(b)
        | Wk::IpPrefix(b)
        | Wk::Ipv4Prefix(b)
        | Wk::Ipv6Prefix(b)
        | Wk::HostAndPort(b)
        | Wk::Ulid(b)
        | Wk::ProtobufFqn(b)
        | Wk::ProtobufDotFqn(b) => *b && number != 24,
        Wk::WellKnownRegex(_) => number == 24,
    }
}

pub(super) fn checks(prefix: &str, r: &StringRules, number: u32) -> Result<Vec<Native>, Error> {
    let str_check = |suffix: &str, message: String, test: StrTest| {
        Ok(vec![Native::new(prefix, suffix, message, Test::Str(test))])
    };
    match number {
        1 => {
            let c = r.r#const.clone().unwrap_or_default();
            str_check("const", format!("must equal `{c}`"), StrTest::Const(c))
        }
        6 => {
            let p = r.pattern.clone().unwrap_or_default();
            let compiled = regex(&p)?;
            str_check(
                "pattern",
                format!("does not match regex pattern `{p}`"),
                StrTest::Pattern(compiled),
            )
        }
        10 => str_check(
            "in",
            format!("must be in list {}", List(&r.r#in)),
            StrTest::In(r.r#in.clone()),
        ),
        11 => str_check(
            "not_in",
            format!("must not be in list {}", List(&r.not_in)),
            StrTest::NotIn(r.not_in.clone()),
        ),
        2..=5 | 19 | 20 => Ok(string_length_check(prefix, r, number).into_iter().collect()),
        7..=9 | 23 => Ok(string_substring_check(prefix, r, number)
            .into_iter()
            .collect()),
        _ => Ok(match &r.well_known {
            Some(rule) if well_known_enabled(rule, number) => {
                well_known_checks(prefix, rule, r.strict.unwrap_or(true))
            }
            _ => Vec::new(),
        }),
    }
}

/// The length rules: in characters or in bytes, exact, at least or at most.
fn string_length_check(prefix: &str, r: &StringRules, number: u32) -> Option<Native> {
    let (suffix, message, test) = match number {
        2 => {
            let n = r.min_len.unwrap_or_default();
            (
                "min_len",
                format!("must be at least {n} characters"),
                StrTest::MinLen(n),
            )
        }
        3 => {
            let n = r.max_len.unwrap_or_default();
            (
                "max_len",
                format!("must be at most {n} characters"),
                StrTest::MaxLen(n),
            )
        }
        4 => {
            let n = r.min_bytes.unwrap_or_default();
            (
                "min_bytes",
                format!("must be at least {n} bytes"),
                StrTest::MinBytes(n),
            )
        }
        5 => {
            let n = r.max_bytes.unwrap_or_default();
            (
                "max_bytes",
                format!("must be at most {n} bytes"),
                StrTest::MaxBytes(n),
            )
        }
        19 => {
            let n = r.len.unwrap_or_default();
            ("len", format!("must be {n} characters"), StrTest::Len(n))
        }
        20 => {
            let n = r.len_bytes.unwrap_or_default();
            (
                "len_bytes",
                format!("must be {n} bytes"),
                StrTest::LenBytes(n),
            )
        }
        _ => return None,
    };
    Some(Native::new(prefix, suffix, message, Test::Str(test)))
}

/// The substring rules: `prefix`, `suffix`, `contains` and `not_contains`.
fn string_substring_check(prefix: &str, r: &StringRules, number: u32) -> Option<Native> {
    let (suffix, message, test) = match number {
        7 => {
            let p = r.prefix.clone().unwrap_or_default();
            (
                "prefix",
                format!("does not have prefix `{p}`"),
                StrTest::Prefix(p),
            )
        }
        8 => {
            let p = r.suffix.clone().unwrap_or_default();
            (
                "suffix",
                format!("does not have suffix `{p}`"),
                StrTest::Suffix(p),
            )
        }
        9 => {
            let p = r.contains.clone().unwrap_or_default();
            (
                "contains",
                format!("does not contain substring `{p}`"),
                StrTest::Contains(p),
            )
        }
        23 => {
            let p = r.not_contains.clone().unwrap_or_default();
            (
                "not_contains",
                format!("contains substring `{p}`"),
                StrTest::NotContains(p),
            )
        }
        _ => return None,
    };
    Some(Native::new(prefix, suffix, message, Test::Str(test)))
}

/// A well-known format and, when `empty` names what an empty string is
/// not, its `_empty` companion.
fn well_known(
    prefix: &str,
    suffix: &str,
    what: &str,
    format: WellKnown,
    empty: Option<&str>,
) -> Vec<Native> {
    let mut checks = vec![Native::new(
        prefix,
        suffix,
        format!("must be a valid {what}"),
        Test::Str(StrTest::WellKnown(format)),
    )];
    if let Some(empty) = empty {
        checks.push(Native::new(
            prefix,
            &format!("{suffix}_empty"),
            format!("value is empty, which is not a valid {empty}"),
            Test::Str(StrTest::Empty),
        ));
    }
    checks
}

/// The checks of a well-known format rule that is set.
fn well_known_checks(
    prefix: &str,
    rule: &oneof::string_rules::WellKnown,
    strict: bool,
) -> Vec<Native> {
    use oneof::string_rules::WellKnown as Wk;
    let simple = |suffix: &str, what: &str, format: WellKnown| {
        well_known(prefix, suffix, what, format, Some(what))
    };
    match rule {
        Wk::Email(_) => simple("email", "email address", WellKnown::Email),
        Wk::Hostname(_) => simple("hostname", "hostname", WellKnown::Hostname),
        Wk::Ip(_) => simple("ip", "IP address", WellKnown::Ip),
        Wk::Ipv4(_) => simple("ipv4", "IPv4 address", WellKnown::Ipv4),
        Wk::Ipv6(_) => simple("ipv6", "IPv6 address", WellKnown::Ipv6),
        Wk::Uri(_) => simple("uri", "URI", WellKnown::Uri),
        Wk::UriRef(_) => well_known(prefix, "uri_ref", "URI Reference", WellKnown::UriRef, None),
        Wk::Address(_) => simple("address", "hostname, or ip address", WellKnown::Address),
        Wk::Uuid(_) => simple("uuid", "UUID", WellKnown::Uuid),
        Wk::Tuuid(_) => simple("tuuid", "trimmed UUID", WellKnown::Tuuid),
        Wk::IpWithPrefixlen(_) => {
            simple("ip_with_prefixlen", "IP prefix", WellKnown::IpWithPrefixlen)
        }
        Wk::Ipv4WithPrefixlen(_) => simple(
            "ipv4_with_prefixlen",
            "IPv4 address with prefix length",
            WellKnown::Ipv4WithPrefixlen,
        ),
        Wk::Ipv6WithPrefixlen(_) => simple(
            "ipv6_with_prefixlen",
            "IPv6 address with prefix length",
            WellKnown::Ipv6WithPrefixlen,
        ),
        Wk::IpPrefix(_) => simple("ip_prefix", "IP prefix", WellKnown::IpPrefix),
        Wk::Ipv4Prefix(_) => simple("ipv4_prefix", "IPv4 prefix", WellKnown::Ipv4Prefix),
        Wk::Ipv6Prefix(_) => simple("ipv6_prefix", "IPv6 prefix", WellKnown::Ipv6Prefix),
        Wk::HostAndPort(_) => well_known(
            prefix,
            "host_and_port",
            "host (hostname or IP address) and port pair",
            WellKnown::HostAndPort,
            Some("host and port pair"),
        ),
        Wk::Ulid(_) => simple("ulid", "ULID", WellKnown::Ulid),
        Wk::ProtobufFqn(_) => simple(
            "protobuf_fqn",
            "fully-qualified Protobuf name",
            WellKnown::ProtobufFqn,
        ),
        Wk::ProtobufDotFqn(_) => simple(
            "protobuf_dot_fqn",
            "fully-qualified Protobuf name with a leading dot",
            WellKnown::ProtobufDotFqn,
        ),
        Wk::WellKnownRegex(KnownRegex::KNOWN_REGEX_HTTP_HEADER_NAME) => simple(
            "well_known_regex.header_name",
            "HTTP header name",
            WellKnown::HeaderName { strict },
        ),
        Wk::WellKnownRegex(KnownRegex::KNOWN_REGEX_HTTP_HEADER_VALUE) => well_known(
            prefix,
            "well_known_regex.header_value",
            "HTTP header value",
            WellKnown::HeaderValue { strict },
            None,
        ),
        Wk::WellKnownRegex(_) => Vec::new(),
    }
}
