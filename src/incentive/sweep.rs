//! A grid of parameter points, and one row of results per point.
//!
//! [`Report`] answers "does the mechanism hold
//! *here*". Tuning asks a different question -- "where does it stop holding" --
//! and the only way to answer it with a single-point evaluator was to invoke
//! the CLI by hand and compare printed reports by eye. This module runs the
//! same evaluation across a grid and emits a table.
//!
//! Three things are deliberate:
//!
//! **No new evaluation.** A row is [`Report`] with the fields flattened
//! out; nothing here re-derives a payoff. If the sweep and the single-point
//! report ever disagree about a point, the sweep is wrong by construction, and
//! that is the property worth having in a tool people tune parameters against.
//!
//! **An invalid point is a row, not an abort.** Grids run through combinations
//! nobody chose: `canary_rate + fraud_rate > 1` is refused by
//! [`NodeParams::validate`], and a sweep that stopped at the first such point
//! would report a table that silently ended early. Those points carry their
//! error in the `error` column and the sweep continues.
//!
//! **Endpoints are exact, interiors are snapped.** A rate's denominator is
//! bounded by [`MAX_RATE_DEN`], and interpolating between two arbitrary
//! fractions does not respect that bound -- adding rationals multiplies
//! denominators. Interior points are therefore rounded to the nearest
//! `1/MAX_RATE_DEN`, while the two endpoints are passed through exactly as the
//! operator typed them. The alternative, snapping everything, would quietly
//! evaluate a different point than the one asked for at the two values the
//! operator is most likely to care about.

use std::fmt;

use crate::canonical::Value;
use crate::incentive::design::Report;
use crate::incentive::exact::Rat;
use crate::incentive::game::Stability;
use crate::incentive::{NodeParams, MAX_RATE_DEN};

/// How many points an axis written as a bare range gets.
const DEFAULT_STEPS: u32 = 5;

/// Ceiling on grid size. Not a resource limit -- a typo limit: `stake=0..10000000:1000000`
/// is a mistyped step count far more often than it is a request, and a sweep
/// that big is minutes of silence before the first row appears.
pub const MAX_POINTS: usize = 10_000;

/// What kind of value a knob takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An exact fraction in `[0, 1]`.
    Rate,
    /// A count of things: nodes, committee seats.
    Count,
    /// Money, in units.
    Units,
}

/// One value of one knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Point {
    Rate(Rat),
    Count(u32),
    Units(u64),
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Point::Rate(rate) => write!(f, "{rate}"),
            Point::Count(count) => write!(f, "{count}"),
            Point::Units(units) => write!(f, "{units}"),
        }
    }
}

/// A [`NodeParams`] field a sweep can vary.
///
/// The names are the `incentives` flags without their leading dashes, so
/// `--sweep canary-rate=..` and `--canary-rate ..` name the same field. A knob
/// per flag rather than a generic setter because the flags are the vocabulary
/// an operator already has, and a sweep over a field with no flag would be a
/// value they could not then pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Knob {
    Nodes,
    Settled,
    Fee,
    Stake,
    SlashRate,
    VerifyCost,
    StorageCost,
    OperatingCost,
    CanaryRate,
    CanaryLeak,
    FraudRate,
    CatchBounty,
    AuditRate,
    Committee,
    Threshold,
    SealedValue,
    DetectionRate,
}

/// Every knob, in the order `incentives --help` lists the matching flags.
pub const KNOBS: [Knob; 17] = [
    Knob::Nodes,
    Knob::Settled,
    Knob::Fee,
    Knob::Stake,
    Knob::SlashRate,
    Knob::VerifyCost,
    Knob::StorageCost,
    Knob::OperatingCost,
    Knob::CanaryRate,
    Knob::CanaryLeak,
    Knob::FraudRate,
    Knob::CatchBounty,
    Knob::AuditRate,
    Knob::Committee,
    Knob::Threshold,
    Knob::SealedValue,
    Knob::DetectionRate,
];

impl Knob {
    pub fn name(self) -> &'static str {
        match self {
            Knob::Nodes => "nodes",
            Knob::Settled => "settled",
            Knob::Fee => "fee",
            Knob::Stake => "stake",
            Knob::SlashRate => "slash-rate",
            Knob::VerifyCost => "verify-cost",
            Knob::StorageCost => "storage-cost",
            Knob::OperatingCost => "operating-cost",
            Knob::CanaryRate => "canary-rate",
            Knob::CanaryLeak => "canary-leak",
            Knob::FraudRate => "fraud-rate",
            Knob::CatchBounty => "catch-bounty",
            Knob::AuditRate => "audit-rate",
            Knob::Committee => "committee",
            Knob::Threshold => "threshold",
            Knob::SealedValue => "sealed-value",
            Knob::DetectionRate => "detection-rate",
        }
    }

    pub fn from_name(name: &str) -> Option<Knob> {
        KNOBS.into_iter().find(|knob| knob.name() == name)
    }

    pub fn kind(self) -> Kind {
        match self {
            Knob::Nodes | Knob::Committee | Knob::Threshold => Kind::Count,
            Knob::Fee
            | Knob::SlashRate
            | Knob::CanaryRate
            | Knob::CanaryLeak
            | Knob::FraudRate
            | Knob::AuditRate
            | Knob::DetectionRate => Kind::Rate,
            Knob::Settled
            | Knob::Stake
            | Knob::VerifyCost
            | Knob::StorageCost
            | Knob::OperatingCost
            | Knob::CatchBounty
            | Knob::SealedValue => Kind::Units,
        }
    }

    /// Write one value into a parameter set.
    ///
    /// A [`Point`] of the wrong shape is a bug in this module, not an operator
    /// error -- [`Axis::parse`] builds points from `kind()` -- so it is left
    /// unchanged rather than reported: silently doing nothing is worse than a
    /// wrong number only when nothing else checks, and `validate` runs after.
    pub fn apply(self, params: &mut NodeParams, point: Point) {
        match (self, point) {
            (Knob::Nodes, Point::Count(value)) => params.nodes = value,
            (Knob::Committee, Point::Count(value)) => params.committee = value,
            (Knob::Threshold, Point::Count(value)) => params.threshold = value,
            (Knob::Settled, Point::Units(value)) => params.settled_value = value,
            (Knob::Stake, Point::Units(value)) => params.stake = value,
            (Knob::VerifyCost, Point::Units(value)) => params.verify_cost = value,
            (Knob::StorageCost, Point::Units(value)) => params.storage_cost = value,
            (Knob::OperatingCost, Point::Units(value)) => params.operating_cost = value,
            (Knob::CatchBounty, Point::Units(value)) => params.catch_bounty = value,
            (Knob::SealedValue, Point::Units(value)) => params.sealed_value = value,
            (Knob::Fee, Point::Rate(value)) => params.fee = value,
            (Knob::SlashRate, Point::Rate(value)) => params.slash_rate = value,
            (Knob::CanaryRate, Point::Rate(value)) => params.canary_rate = value,
            (Knob::CanaryLeak, Point::Rate(value)) => params.canary_leak = value,
            (Knob::FraudRate, Point::Rate(value)) => params.fraud_rate = value,
            (Knob::AuditRate, Point::Rate(value)) => params.audit_rate = value,
            (Knob::DetectionRate, Point::Rate(value)) => params.detection_rate = value,
            _ => {}
        }
    }
}

/// What went wrong reading an axis off the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepError {
    /// No `=` in the spec.
    NoAssignment { spec: String },
    /// The left-hand side names no knob.
    UnknownKnob { name: String },
    /// A bound would not parse as this knob's kind.
    BadValue {
        knob: &'static str,
        text: String,
        kind: Kind,
    },
    /// `:0`, or a step count that is not a number.
    BadSteps { spec: String, text: String },
    /// The product of the axes exceeds [`MAX_POINTS`].
    TooManyPoints { points: usize },
}

impl fmt::Display for SweepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SweepError::NoAssignment { spec } => write!(
                f,
                "--sweep {spec:?}: expected NAME=LO..HI[:STEPS], e.g. canary-rate=1/20..1/5:5"
            ),
            SweepError::UnknownKnob { name } => {
                write!(f, "--sweep: {name:?} is not a sweepable parameter (")?;
                for (index, knob) in KNOBS.iter().enumerate() {
                    if index > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", knob.name())?;
                }
                write!(f, ")")
            }
            SweepError::BadValue { knob, text, kind } => {
                let expected = match kind {
                    Kind::Rate => "an exact fraction in [0, 1] such as 1/100",
                    Kind::Count => "a whole number of things",
                    Kind::Units => "a whole number of units",
                };
                write!(f, "--sweep {knob}: expected {expected}, got {text:?}")
            }
            SweepError::BadSteps { spec, text } => write!(
                f,
                "--sweep {spec:?}: {text:?} is not a step count of at least 1"
            ),
            SweepError::TooManyPoints { points } => write!(
                f,
                "--sweep: {points} grid points exceeds the {MAX_POINTS} ceiling; \
                 narrow a range or lower a step count"
            ),
        }
    }
}

impl std::error::Error for SweepError {}

/// One swept parameter and every value it takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Axis {
    pub knob: Knob,
    pub values: Vec<Point>,
}

impl Axis {
    /// Read `NAME=LO..HI[:STEPS]`, or `NAME=VALUE` for a single point.
    ///
    /// `STEPS` counts *points*, not intervals, so `1/20..1/5:5` yields five
    /// values with both ends included. Duplicates that integer rounding
    /// produces -- `committee=3..4:9` cannot have nine distinct values -- are
    /// dropped, because a repeated row is not a second measurement.
    pub fn parse(spec: &str) -> Result<Axis, SweepError> {
        let (name, rest) = spec
            .split_once('=')
            .ok_or_else(|| SweepError::NoAssignment {
                spec: spec.to_string(),
            })?;
        let name = name.trim();
        let knob = Knob::from_name(name).ok_or_else(|| SweepError::UnknownKnob {
            name: name.to_string(),
        })?;

        // Split the step count off the right. `rsplit_once` rather than
        // `split_once`: nothing in a bound contains a colon today, but taking
        // the *last* one means a future bound that does still parses.
        let (range, steps) = match rest.rsplit_once(':') {
            Some((range, steps)) => {
                let parsed: u32 =
                    steps
                        .trim()
                        .parse()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or_else(|| SweepError::BadSteps {
                            spec: spec.to_string(),
                            text: steps.to_string(),
                        })?;
                (range, Some(parsed))
            }
            None => (rest, None),
        };

        let (low_text, high_text) = match range.split_once("..") {
            Some((low, high)) => (low, high),
            // A single value is a one-point axis, which is how an operator
            // pins one parameter while sweeping another without reaching for
            // a second flag with different syntax.
            None => (range, range),
        };
        let low = value(knob, low_text)?;
        let high = value(knob, high_text)?;
        let steps = steps.unwrap_or(if low == high { 1 } else { DEFAULT_STEPS });

        Ok(Axis {
            knob,
            values: interpolate(low, high, steps),
        })
    }
}

fn value(knob: Knob, text: &str) -> Result<Point, SweepError> {
    let text = text.trim();
    let bad = || SweepError::BadValue {
        knob: knob.name(),
        text: text.to_string(),
        kind: knob.kind(),
    };
    match knob.kind() {
        Kind::Count => text.parse().map(Point::Count).map_err(|_| bad()),
        Kind::Units => text.parse().map(Point::Units).map_err(|_| bad()),
        Kind::Rate => {
            let (num, den) = match text.split_once('/') {
                Some((num, den)) => (num, den),
                None => (text, "1"),
            };
            let num: u32 = num.trim().parse().map_err(|_| bad())?;
            let den: u32 = den.trim().parse().map_err(|_| bad())?;
            Rat::rate(num, den).map(Point::Rate).ok_or_else(bad)
        }
    }
}

/// `steps` values from `low` to `high` inclusive.
fn interpolate(low: Point, high: Point, steps: u32) -> Vec<Point> {
    if steps == 1 || low == high {
        return vec![low];
    }
    let last = i128::from(steps - 1);
    let mut out: Vec<Point> = Vec::with_capacity(steps as usize);
    for index in 0..steps {
        let point = if index == 0 {
            low
        } else if index == steps - 1 {
            high
        } else {
            interior(low, high, i128::from(index), last)
        };
        // Integer knobs collapse onto the same value when the range is
        // narrower than the step count.
        if out.last() != Some(&point) {
            out.push(point);
        }
    }
    out
}

fn interior(low: Point, high: Point, index: i128, last: i128) -> Point {
    match (low, high) {
        (Point::Count(low), Point::Count(high)) => {
            Point::Count(lerp_int(i128::from(low), i128::from(high), index, last) as u32)
        }
        (Point::Units(low), Point::Units(high)) => {
            Point::Units(lerp_int(i128::from(low), i128::from(high), index, last) as u64)
        }
        (Point::Rate(low), Point::Rate(high)) => Point::Rate(lerp_rate(low, high, index, last)),
        // Unreachable: both bounds came from the same `knob.kind()`.
        _ => low,
    }
}

/// `low + (high - low) * index / last`, rounded to nearest, in `i128`.
///
/// Both bounds are bounded by `MAX_UNITS` (2^40) and `last` by the step count,
/// so the product cannot approach `i128`'s range; `saturating_*` is here so
/// that stays true rather than because it is reached.
fn lerp_int(low: i128, high: i128, index: i128, last: i128) -> i128 {
    let span = high.saturating_sub(low);
    let scaled = span.saturating_mul(index);
    // Round half away from zero, so a midpoint does not systematically favour
    // the lower end of every range.
    let half = last / 2;
    let rounded = if scaled >= 0 {
        (scaled + half) / last
    } else {
        (scaled - half) / last
    };
    low.saturating_add(rounded)
}

/// The same interpolation for rates, snapped to a denominator
/// [`NodeParams::validate`] accepts. See the module docs.
fn lerp_rate(low: Rat, high: Rat, index: i128, last: i128) -> Rat {
    let numerator = low
        .numerator()
        .saturating_mul(last.saturating_sub(index))
        .saturating_mul(high.denominator())
        .saturating_add(
            high.numerator()
                .saturating_mul(index)
                .saturating_mul(low.denominator()),
        );
    let denominator = low
        .denominator()
        .saturating_mul(high.denominator())
        .saturating_mul(last);
    if denominator == 0 {
        return low;
    }
    // Round to the nearest 1/MAX_RATE_DEN. The exact value is
    // `numerator / denominator`; scaling by the grid and rounding gives a
    // fraction whose denominator divides MAX_RATE_DEN, which is what makes it
    // survive validation however awkward the endpoints were.
    let scaled = numerator.saturating_mul(MAX_RATE_DEN);
    let ticks = (scaled + denominator / 2) / denominator;
    let ticks = ticks.clamp(0, MAX_RATE_DEN);
    Rat::new(ticks, MAX_RATE_DEN).unwrap_or(low)
}

/// Every combination of the axes' values, last axis varying fastest.
///
/// Order matters for a table an operator reads down: with the last axis
/// innermost, consecutive rows differ in one column, which is what makes a
/// threshold visible without sorting.
pub fn grid(axes: &[Axis]) -> Result<Vec<Vec<Point>>, SweepError> {
    let mut points: usize = 1;
    for axis in axes {
        points = points.saturating_mul(axis.values.len());
    }
    if points > MAX_POINTS {
        return Err(SweepError::TooManyPoints { points });
    }
    let mut rows: Vec<Vec<Point>> = vec![Vec::new()];
    for axis in axes {
        let mut next = Vec::with_capacity(rows.len().saturating_mul(axis.values.len()));
        for row in &rows {
            for value in &axis.values {
                let mut extended = row.clone();
                extended.push(*value);
                next.push(extended);
            }
        }
        rows = next;
    }
    Ok(rows)
}

/// One evaluated grid point, flattened into named cells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub cells: Vec<(String, String)>,
}

impl Row {
    fn get(&self, name: &str) -> Option<&str> {
        self.cells
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Whether this point's mechanism held. `false` for a point that could not
    /// be evaluated at all -- an unevaluable point is not a passing one.
    pub fn passes(&self) -> bool {
        self.get("verdict") == Some("ok")
    }
}

/// Evaluate every point of the grid against `base`.
///
/// `base` supplies every parameter no axis names, so a sweep inherits the
/// `--nodes`/`--fee`/... flags on the same command line rather than silently
/// reverting to the reference set.
///
/// `progress` is called once per point before it is evaluated, with
/// `(done, total)`. A grid of a few hundred points takes long enough that
/// silence is indistinguishable from a hang.
pub fn run(
    base: &NodeParams,
    axes: &[Axis],
    mut progress: impl FnMut(usize, usize),
) -> Result<Vec<Row>, SweepError> {
    let points = grid(axes)?;
    let total = points.len();
    let mut rows = Vec::with_capacity(total);
    for (index, assignment) in points.iter().enumerate() {
        progress(index, total);
        let mut params = base.clone();
        for (axis, point) in axes.iter().zip(assignment) {
            axis.knob.apply(&mut params, *point);
        }
        rows.push(row_for(axes, assignment, &params));
    }
    Ok(rows)
}

fn row_for(axes: &[Axis], assignment: &[Point], params: &NodeParams) -> Row {
    let mut cells: Vec<(String, String)> = axes
        .iter()
        .zip(assignment)
        .map(|(axis, point)| (axis.knob.name().to_string(), point.to_string()))
        .collect();

    match Report::of(params) {
        Ok(report) => {
            cells.push(("verdict".into(), mark(report.passes())));
            cells.push(("revenue".into(), report.participation.revenue.to_decimal(2)));
            cells.push(("cost".into(), report.participation.cost.to_decimal(2)));
            cells.push(("net".into(), report.participation.net.to_decimal(2)));
            cells.push((
                "supports_nodes".into(),
                option_or(report.participation.supports_nodes, "none"),
            ));
            cells.push((
                "break_even_settled".into(),
                option_or(report.participation.break_even_settled_value, "unreachable"),
            ));
            cells.push((
                "sybil_gain".into(),
                report
                    .sybil
                    .iter()
                    .find(|(rule, _, _)| *rule == report.params.reward_rule)
                    .map(|(_, _, gain)| gain.to_decimal(4))
                    .unwrap_or_else(|| String::from("?")),
            ));
            cells.push((
                "committee_thresholds".into(),
                match (
                    report.committee_window.first(),
                    report.committee_window.last(),
                ) {
                    (Some(low), Some(high)) => format!("{low}..{high}"),
                    _ => String::from("none"),
                },
            ));
            for service in &report.services {
                let prefix = service.service;
                cells.push((
                    format!("{prefix}_stability"),
                    match service.stability {
                        Some(Stability::Strict) => String::from("strict"),
                        Some(Stability::Weak) => String::from("weak"),
                        None => String::from("none"),
                    },
                ));
                cells.push((format!("{prefix}_rivals"), service.rivals.len().to_string()));
                cells.push((
                    format!("{prefix}_defection"),
                    service
                        .defection
                        .as_ref()
                        .map(|found| found.mutants.to_string())
                        .unwrap_or_else(|| String::from("none")),
                ));
                cells.push((
                    format!("{prefix}_tipping"),
                    option_or(service.tipping, "recovers"),
                ));
                cells.push((
                    format!("{prefix}_exact"),
                    if service.exact { "yes" } else { "no" }.to_string(),
                ));
                cells.push((
                    format!("{prefix}_binding"),
                    service.binding.clone().unwrap_or_default(),
                ));
            }
            cells.push(("error".into(), String::new()));
        }
        // Not a failure of the sweep: a grid runs through parameter
        // combinations nobody chose. The row carries the reason so the gap in
        // the table is explained rather than merely present.
        Err(error) => {
            cells.push(("verdict".into(), String::from("invalid")));
            cells.push(("error".into(), error.to_string()));
        }
    }
    Row { cells }
}

fn mark(passed: bool) -> String {
    String::from(if passed { "ok" } else { "FAIL" })
}

fn option_or<T: fmt::Display>(value: Option<T>, absent: &str) -> String {
    value.map_or_else(|| absent.to_string(), |value| value.to_string())
}

/// Column names, in order, across every row.
///
/// A row that could not be evaluated is missing the report columns, so the
/// header is the union rather than the first row's keys -- otherwise a grid
/// whose first point happened to be invalid would emit a two-column table.
pub fn header(rows: &[Row]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for row in rows {
        for (key, _) in &row.cells {
            if !names.iter().any(|existing| existing == key) {
                names.push(key.clone());
            }
        }
    }
    names
}

/// The rows as CSV, header first, `\n`-terminated.
pub fn to_csv(rows: &[Row]) -> String {
    let names = header(rows);
    let mut out = String::new();
    push_csv_record(&mut out, names.iter().map(String::as_str));
    for row in rows {
        push_csv_record(
            &mut out,
            names.iter().map(|name| row.get(name).unwrap_or("")),
        );
    }
    out
}

fn push_csv_record<'a>(out: &mut String, fields: impl Iterator<Item = &'a str>) {
    let mut first = true;
    for field in fields {
        if !first {
            out.push(',');
        }
        first = false;
        // Quote whenever a bare field would be ambiguous. Binding-constraint
        // text is prose written elsewhere in this crate, so this cannot assume
        // anything about what is in it.
        if field.contains([',', '"', '\n', '\r']) {
            out.push('"');
            for character in field.chars() {
                if character == '"' {
                    out.push('"');
                }
                out.push(character);
            }
            out.push('"');
        } else {
            out.push_str(field);
        }
    }
    out.push('\n');
}

/// The rows as JSON Lines, one object per point.
///
/// Written through [`crate::canonical`] rather than by hand: it is the crate's
/// one JSON encoder, and a second one here would be a second set of escaping
/// rules. Keys come out sorted, so read the column *names*, not their order.
pub fn to_jsonl(rows: &[Row]) -> String {
    let mut out = String::new();
    for row in rows {
        let object = Value::object(
            row.cells
                .iter()
                .map(|(key, value)| (key.clone(), Value::string(value))),
        );
        out.push_str(&object.canonical_string());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_includes_both_endpoints_exactly_as_typed() {
        let axis = Axis::parse("canary-rate=1/20..1/5:5").expect("parses");
        assert_eq!(axis.knob, Knob::CanaryRate);
        assert_eq!(axis.values.len(), 5);
        assert_eq!(axis.values[0], Point::Rate(Rat::rate(1, 20).unwrap()));
        assert_eq!(axis.values[4], Point::Rate(Rat::rate(1, 5).unwrap()));
    }

    /// The property the module docs promise: whatever the endpoints, every
    /// value a sweep produces is one `validate` accepts.
    #[test]
    fn interior_rates_stay_inside_the_denominator_bound() {
        let axis = Axis::parse("canary-rate=1/7..1/3:9").expect("parses");
        for value in &axis.values {
            match value {
                Point::Rate(rate) => {
                    assert!(rate.denominator() <= MAX_RATE_DEN, "{rate} is too fine");
                    assert!(!rate.is_negative() && *rate <= Rat::ONE);
                }
                other => panic!("expected a rate, got {other}"),
            }
        }
    }

    #[test]
    fn a_bare_value_is_a_one_point_axis() {
        let axis = Axis::parse("stake=4000").expect("parses");
        assert_eq!(axis.values, vec![Point::Units(4000)]);
    }

    #[test]
    fn integer_ranges_do_not_repeat_a_value() {
        let axis = Axis::parse("committee=3..4:9").expect("parses");
        assert_eq!(axis.values, vec![Point::Count(3), Point::Count(4)]);
    }

    #[test]
    fn an_integer_range_walks_its_span() {
        let axis = Axis::parse("stake=1000..10000:4").expect("parses");
        assert_eq!(
            axis.values,
            vec![
                Point::Units(1000),
                Point::Units(4000),
                Point::Units(7000),
                Point::Units(10000),
            ]
        );
    }

    #[test]
    fn malformed_specs_are_refused_with_the_flag_named() {
        assert!(matches!(
            Axis::parse("canary-rate"),
            Err(SweepError::NoAssignment { .. })
        ));
        assert!(matches!(
            Axis::parse("nonsense=1..2"),
            Err(SweepError::UnknownKnob { .. })
        ));
        assert!(matches!(
            Axis::parse("stake=abc..2"),
            Err(SweepError::BadValue { .. })
        ));
        assert!(matches!(
            Axis::parse("stake=1..2:0"),
            Err(SweepError::BadSteps { .. })
        ));
        assert!(matches!(
            Axis::parse("canary-rate=3/2..1"),
            Err(SweepError::BadValue { .. })
        ));
    }

    #[test]
    fn the_grid_is_the_product_with_the_last_axis_innermost() {
        let axes = vec![
            Axis::parse("committee=3..5:3").expect("parses"),
            Axis::parse("threshold=2..3:2").expect("parses"),
        ];
        let points = grid(&axes).expect("small enough");
        assert_eq!(points.len(), 6);
        assert_eq!(points[0], vec![Point::Count(3), Point::Count(2)]);
        assert_eq!(points[1], vec![Point::Count(3), Point::Count(3)]);
        assert_eq!(points[2], vec![Point::Count(4), Point::Count(2)]);
    }

    #[test]
    fn an_oversized_grid_is_refused_rather_than_run() {
        let axes = vec![
            Axis::parse("stake=1..100000:200").expect("parses"),
            Axis::parse("settled=1..100000:200").expect("parses"),
        ];
        assert!(matches!(grid(&axes), Err(SweepError::TooManyPoints { .. })));
    }

    #[test]
    fn a_swept_point_agrees_with_the_single_point_report() {
        let base = NodeParams::reference();
        let axes = vec![Axis::parse("stake=4000").expect("parses")];
        let rows = run(&base, &axes, |_, _| {}).expect("runs");
        assert_eq!(rows.len(), 1);

        let mut expected = base.clone();
        expected.stake = 4000;
        let report = Report::of(&expected).expect("evaluates");
        assert_eq!(rows[0].passes(), report.passes());
        assert_eq!(
            rows[0].get("net"),
            Some(report.participation.net.to_decimal(2).as_str())
        );
    }

    /// A grid runs through combinations nobody chose. The sweep must survive
    /// them: `threshold > committee` is refused by `validate`.
    #[test]
    fn an_invalid_point_becomes_a_row_and_does_not_stop_the_sweep() {
        let base = NodeParams::reference();
        let axes = vec![Axis::parse("threshold=1..99:3").expect("parses")];
        let rows = run(&base, &axes, |_, _| {}).expect("runs");
        assert_eq!(rows.len(), 3);
        let invalid = rows
            .iter()
            .filter(|row| row.get("verdict") == Some("invalid"))
            .count();
        assert!(invalid > 0, "expected at least one refused point");
        for row in &rows {
            if row.get("verdict") == Some("invalid") {
                assert!(!row.get("error").unwrap_or("").is_empty());
                assert!(!row.passes());
            }
        }
    }

    #[test]
    fn the_header_is_the_union_so_an_invalid_first_row_does_not_truncate_it() {
        let base = NodeParams::reference();
        // Threshold 99 exceeds the committee, so the first point is refused.
        let axes = vec![Axis::parse("threshold=99..2:2").expect("parses")];
        let rows = run(&base, &axes, |_, _| {}).expect("runs");
        let names = header(&rows);
        assert!(names.iter().any(|name| name == "net"));
        assert!(names.iter().any(|name| name == "error"));
    }

    #[test]
    fn csv_quotes_a_field_that_would_otherwise_split_the_row() {
        let rows = vec![Row {
            cells: vec![
                (String::from("a"), String::from("plain")),
                (String::from("b"), String::from("has, comma and \"quote\"")),
            ],
        }];
        let csv = to_csv(&rows);
        let mut lines = csv.lines();
        assert_eq!(lines.next(), Some("a,b"));
        assert_eq!(lines.next(), Some(r#"plain,"has, comma and ""quote""""#));
    }

    #[test]
    fn jsonl_is_one_object_per_row() {
        let base = NodeParams::reference();
        let axes = vec![Axis::parse("stake=4000..5000:2").expect("parses")];
        let rows = run(&base, &axes, |_, _| {}).expect("runs");
        let text = to_jsonl(&rows);
        assert_eq!(text.lines().count(), 2);
        for line in text.lines() {
            let value = Value::from_json(line).expect("valid json");
            assert!(value.get("stake").is_some());
            assert!(value.get("verdict").is_some());
        }
    }

    #[test]
    fn progress_is_reported_once_per_point() {
        let base = NodeParams::reference();
        let axes = vec![Axis::parse("stake=4000..6000:3").expect("parses")];
        let mut seen = Vec::new();
        let rows = run(&base, &axes, |done, total| seen.push((done, total))).expect("runs");
        assert_eq!(rows.len(), 3);
        assert_eq!(seen, vec![(0, 3), (1, 3), (2, 3)]);
    }

    #[test]
    fn every_knob_names_a_flag_and_applies_to_its_field() {
        let base = NodeParams::reference();
        for knob in KNOBS {
            let point = match knob.kind() {
                Kind::Rate => Point::Rate(Rat::rate(1, 7).expect("a rate")),
                Kind::Count => Point::Count(7),
                Kind::Units => Point::Units(7),
            };
            let mut params = base.clone();
            knob.apply(&mut params, point);
            assert_ne!(params, base, "{} changed nothing", knob.name());
            assert_eq!(Knob::from_name(knob.name()), Some(knob));
        }
    }
}
