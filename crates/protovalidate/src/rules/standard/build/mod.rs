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

//! Building the checks of one rule field.
//!
//! [`checks`] is asked once per rule field a rules message sets, in
//! field-number order, and answers with the checks `validate.proto`
//! attaches to that field: usually one, two for the well-known string
//! formats with their `_empty` companion, none for fields that are not
//! rules (`example`, `strict`, `items`, ...). The messages are formatted
//! here, from the rule values, as the CEL expressions would. This module
//! has the comparison rules; [`string`] and [`misc`] the rest.

mod misc;
mod string;

use std::fmt::Display;

use buffa_types::google::protobuf::{Duration as DurationPb, Timestamp as TimestampPb};
use regex::Regex;

use super::format::{Duration, List, Timestamp};
use super::{Cmp, MaybeNan, NowTest, Test};
use crate::Error;
use crate::validate::__buffa::oneof;
use crate::validate::__buffa::oneof::field_rules::Type as RulesType;
use crate::validate::TimestampRules;

/// A check less its rule path, which the caller knows.
pub(crate) struct Native {
    pub id: String,
    pub message: String,
    pub test: Test,
}

impl Native {
    fn new(prefix: &str, suffix: &str, message: impl Display, test: Test) -> Self {
        Self {
            id: format!("{prefix}.{suffix}"),
            message: message.to_string(),
            test,
        }
    }
}

/// The comparison rules of a numeric, duration or timestamp rules message,
/// with the values already in the type they are compared in.
struct Bounds<T> {
    r#const: Option<T>,
    lt: Option<T>,
    lte: Option<T>,
    gt: Option<T>,
    gte: Option<T>,
    r#in: Vec<T>,
    not_in: Vec<T>,
}

/// Which rule field of a [`Bounds`] a field number names.
#[derive(Clone, Copy)]
enum Bound {
    Const,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
    NotIn,
}

/// Reads the [`Bounds`] out of a rules message whose `less_than` and
/// `greater_than` oneofs live in `$module`; `$const`, `$in` and `$not_in`
/// are the fields outside the oneofs, whose shape varies by message.
macro_rules! bounds {
    ($rules:expr, $module:ident, $convert:expr, $const:expr, $in:expr, $not_in:expr) => {{
        let convert = $convert;
        Bounds {
            r#const: $const.map(|v| convert(v)),
            lt: match &$rules.less_than {
                Some(oneof::$module::LessThan::Lt(v)) => Some(convert(v)),
                _ => None,
            },
            lte: match &$rules.less_than {
                Some(oneof::$module::LessThan::Lte(v)) => Some(convert(v)),
                _ => None,
            },
            gt: match &$rules.greater_than {
                Some(oneof::$module::GreaterThan::Gt(v)) => Some(convert(v)),
                _ => None,
            },
            gte: match &$rules.greater_than {
                Some(oneof::$module::GreaterThan::Gte(v)) => Some(convert(v)),
                _ => None,
            },
            r#in: $in.iter().map(|v| convert(v)).collect(),
            not_in: $not_in.iter().map(|v| convert(v)).collect(),
        }
    }};
}

/// The [`bounds!`] of a numeric rules message, whose `const`, `in` and
/// `not_in` are plain fields.
macro_rules! numeric_bounds {
    ($rules:expr, $module:ident, $convert:expr) => {
        bounds!(
            $rules,
            $module,
            $convert,
            $rules.r#const.as_ref(),
            $rules.r#in,
            $rules.not_in
        )
    };
}

impl<T: Copy + PartialOrd + MaybeNan + Display> Bounds<T> {
    /// The check of one comparison rule field, none when another rule field
    /// takes it over: `lt` and `lte` defer to a `gt` or `gte`, which spells
    /// out the range.
    fn check(&self, prefix: &str, bound: Bound, wrap: fn(Cmp<T>) -> Test) -> Option<Native> {
        let has_lower = self.gt.is_some() || self.gte.is_some();
        let (suffix, message, cmp) = match bound {
            Bound::Const => {
                let c = self.r#const?;
                ("const", format!("must equal {c}"), Cmp::Const(c))
            }
            Bound::Lt => {
                let lt = self.lt?;
                if has_lower {
                    return None;
                }
                ("lt", format!("must be less than {lt}"), Cmp::Lt(lt))
            }
            Bound::Lte => {
                let lte = self.lte?;
                if has_lower {
                    return None;
                }
                (
                    "lte",
                    format!("must be less than or equal to {lte}"),
                    Cmp::Lte(lte),
                )
            }
            Bound::Gt => return self.lower(prefix, self.gt?, "gt", "greater than", wrap),
            Bound::Gte => {
                return self.lower(prefix, self.gte?, "gte", "greater than or equal to", wrap);
            }
            Bound::In => (
                "in",
                format!("must be in list {}", List(&self.r#in)),
                Cmp::In(self.r#in.clone()),
            ),
            Bound::NotIn => (
                "not_in",
                format!("must not be in list {}", List(&self.not_in)),
                Cmp::NotIn(self.not_in.clone()),
            ),
        };
        Some(Native::new(prefix, suffix, message, wrap(cmp)))
    }

    /// The check of `gt` or `gte`, combined with the `lt` or `lte` that is
    /// also set: a range when the bounds are in order, the complement of one
    /// when the upper bound is below the lower.
    fn lower(
        &self,
        prefix: &str,
        lower: T,
        name: &str,
        words: &str,
        wrap: fn(Cmp<T>) -> Test,
    ) -> Option<Native> {
        let is_gte = name == "gte";
        let (upper, upper_name, upper_words) = match (self.lt, self.lte) {
            (Some(lt), _) => (lt, "lt", "less than"),
            (None, Some(lte)) => (lte, "lte", "less than or equal to"),
            (None, None) => {
                let cmp = if is_gte {
                    Cmp::Gte(lower)
                } else {
                    Cmp::Gt(lower)
                };
                let message = format!("must be {words} {lower}");
                return Some(Native::new(prefix, name, message, wrap(cmp)));
            }
        };
        let (suffix, message, cmp) = if upper >= lower {
            (
                format!("{name}_{upper_name}"),
                format!("must be {words} {lower} and {upper_words} {upper}"),
                match (is_gte, upper_name) {
                    (false, "lt") => Cmp::GtLt {
                        gt: lower,
                        lt: upper,
                    },
                    (false, _) => Cmp::GtLte {
                        gt: lower,
                        lte: upper,
                    },
                    (true, "lt") => Cmp::GteLt {
                        gte: lower,
                        lt: upper,
                    },
                    (true, _) => Cmp::GteLte {
                        gte: lower,
                        lte: upper,
                    },
                },
            )
        } else if upper < lower {
            (
                format!("{name}_{upper_name}_exclusive"),
                format!("must be {words} {lower} or {upper_words} {upper}"),
                match (is_gte, upper_name) {
                    (false, "lt") => Cmp::GtLtExclusive {
                        gt: lower,
                        lt: upper,
                    },
                    (false, _) => Cmp::GtLteExclusive {
                        gt: lower,
                        lte: upper,
                    },
                    (true, "lt") => Cmp::GteLtExclusive {
                        gte: lower,
                        lt: upper,
                    },
                    (true, _) => Cmp::GteLteExclusive {
                        gte: lower,
                        lte: upper,
                    },
                },
            )
        } else {
            // Unordered (a NaN bound): neither expression applies.
            return None;
        };
        Some(Native::new(prefix, &suffix, message, wrap(cmp)))
    }
}

/// The rule field of a numeric rules message a field number names.
fn numeric_bound(number: u32) -> Option<Bound> {
    Some(match number {
        1 => Bound::Const,
        2 => Bound::Lt,
        3 => Bound::Lte,
        4 => Bound::Gt,
        5 => Bound::Gte,
        6 => Bound::In,
        7 => Bound::NotIn,
        _ => return None,
    })
}

/// The rule field of the duration and timestamp rules messages a field
/// number names; they leave field 1 unused.
fn message_bound(number: u32) -> Option<Bound> {
    numeric_bound(number.checked_sub(1)?)
}

fn duration(d: &DurationPb) -> Duration {
    Duration(i128::from(d.seconds) * 1_000_000_000 + i128::from(d.nanos))
}

fn timestamp(t: &TimestampPb) -> Timestamp {
    Timestamp(i128::from(t.seconds) * 1_000_000_000 + i128::from(t.nanos))
}

pub(super) fn regex(pattern: &str) -> Result<Regex, Error> {
    Regex::new(pattern)
        .map_err(|error| Error::Compilation(format!("invalid regex pattern `{pattern}`: {error}")))
}

/// The checks of rule field `number` of `rules`; `prefix` is the rule id's
/// type, `string` say.
pub(crate) fn checks(prefix: &str, rules: &RulesType, number: u32) -> Result<Vec<Native>, Error> {
    let one = |native: Option<Native>| Ok(native.into_iter().collect());
    match rules {
        RulesType::Float(r) => {
            let bounds = numeric_bounds!(r, float_rules, |v: &f32| f64::from(*v));
            Ok(floating(prefix, number, r.finite, &bounds))
        }
        RulesType::Double(r) => {
            let bounds = numeric_bounds!(r, double_rules, |v: &f64| *v);
            Ok(floating(prefix, number, r.finite, &bounds))
        }
        RulesType::Int32(r) => one(numeric(
            prefix,
            number,
            &numeric_bounds!(r, int32rules, |v: &i32| i64::from(*v)),
            Test::Int,
        )),
        RulesType::Int64(r) => one(numeric(
            prefix,
            number,
            &numeric_bounds!(r, int64rules, |v: &i64| *v),
            Test::Int,
        )),
        RulesType::Uint32(r) => one(numeric(
            prefix,
            number,
            &numeric_bounds!(r, u_int32rules, |v: &u32| u64::from(*v)),
            Test::Uint,
        )),
        RulesType::Uint64(r) => one(numeric(
            prefix,
            number,
            &numeric_bounds!(r, u_int64rules, |v: &u64| *v),
            Test::Uint,
        )),
        RulesType::Sint32(r) => one(numeric(
            prefix,
            number,
            &numeric_bounds!(r, s_int32rules, |v: &i32| i64::from(*v)),
            Test::Int,
        )),
        RulesType::Sint64(r) => one(numeric(
            prefix,
            number,
            &numeric_bounds!(r, s_int64rules, |v: &i64| *v),
            Test::Int,
        )),
        RulesType::Fixed32(r) => one(numeric(
            prefix,
            number,
            &numeric_bounds!(r, fixed32rules, |v: &u32| u64::from(*v)),
            Test::Uint,
        )),
        RulesType::Fixed64(r) => one(numeric(
            prefix,
            number,
            &numeric_bounds!(r, fixed64rules, |v: &u64| *v),
            Test::Uint,
        )),
        RulesType::Sfixed32(r) => one(numeric(
            prefix,
            number,
            &numeric_bounds!(r, s_fixed32rules, |v: &i32| i64::from(*v)),
            Test::Int,
        )),
        RulesType::Sfixed64(r) => one(numeric(
            prefix,
            number,
            &numeric_bounds!(r, s_fixed64rules, |v: &i64| *v),
            Test::Int,
        )),
        RulesType::Duration(r) => {
            let bounds = bounds!(
                r,
                duration_rules,
                duration,
                r.r#const.as_option(),
                r.r#in,
                r.not_in
            );
            one(message_bound(number).and_then(|b| bounds.check(prefix, b, Test::Duration)))
        }
        RulesType::Timestamp(r) => one(timestamp_check(prefix, r, number)),
        RulesType::Bool(r) => one(misc::bool_check(prefix, r, number)),
        RulesType::Enum(r) => one(misc::enum_check(prefix, r, number)),
        RulesType::String(r) => string::checks(prefix, r, number),
        RulesType::Bytes(r) => misc::bytes_checks(prefix, r, number),
        RulesType::Repeated(r) => one(misc::repeated_check(prefix, r, number)),
        RulesType::Map(r) => one(misc::map_check(prefix, r, number)),
        RulesType::FieldMask(r) => one(misc::field_mask_check(prefix, r, number)),
        // `any.in` and `any.not_in` are checked with the field's `Any`.
        RulesType::Any(_) => Ok(Vec::new()),
    }
}

/// The check of rule field `number` of an integer rules message.
fn numeric<T: Copy + PartialOrd + MaybeNan + Display>(
    prefix: &str,
    number: u32,
    bounds: &Bounds<T>,
    wrap: fn(Cmp<T>) -> Test,
) -> Option<Native> {
    numeric_bound(number).and_then(|b| bounds.check(prefix, b, wrap))
}

/// The checks of rule field `number` of a float or double rules message,
/// which add `finite` to the integer rules.
fn floating(prefix: &str, number: u32, finite: Option<bool>, bounds: &Bounds<f64>) -> Vec<Native> {
    if number == 8 {
        return match finite {
            Some(true) => vec![Native::new(
                prefix,
                "finite",
                "must be finite",
                Test::Finite,
            )],
            _ => Vec::new(),
        };
    }
    numeric(prefix, number, bounds, Test::Double)
        .into_iter()
        .collect()
}

fn timestamp_check(prefix: &str, r: &TimestampRules, number: u32) -> Option<Native> {
    match number {
        7 => match r.less_than {
            Some(oneof::timestamp_rules::LessThan::LtNow(true)) => Some(Native::new(
                prefix,
                "lt_now",
                "must be less than now",
                Test::Now(NowTest::LtNow),
            )),
            _ => None,
        },
        8 => match r.greater_than {
            Some(oneof::timestamp_rules::GreaterThan::GtNow(true)) => Some(Native::new(
                prefix,
                "gt_now",
                "must be greater than now",
                Test::Now(NowTest::GtNow),
            )),
            _ => None,
        },
        9 => r.within.as_option().map(|within| {
            let within = duration(within);
            Native::new(
                prefix,
                "within",
                format!("must be within {within} of now"),
                Test::Now(NowTest::Within(within)),
            )
        }),
        _ => {
            let none: [TimestampPb; 0] = [];
            let bounds = bounds!(
                r,
                timestamp_rules,
                timestamp,
                r.r#const.as_option(),
                none,
                none
            );
            message_bound(number).and_then(|b| bounds.check(prefix, b, Test::Timestamp))
        }
    }
}
