//! A starting point for a new objective: the files, not the decision.
//!
//! Every objective in `examples/` is hand-written -- an `objective.json`, a
//! checker matched to one of the five verifier kinds, and usually an example
//! artifact. Getting from "I have an idea for a challenge" to something
//! postable meant copying the closest example and editing it, which is how a
//! stale pin or a spec field belonging to a different kind gets carried across.
//!
//! What this generates is a *starting point a human edits*, and the boundary is
//! deliberate in two directions:
//!
//! **It never posts.** The output is files on disk and a printed
//! `proofwork post` line. An objective's statement is untrusted text funded by
//! a human decision, and a tool that both writes and funds one removes the step
//! where that decision happens.
//!
//! **It never judges a checker.** The pinned verifier is the only authority on
//! what a submission needs -- `Objective::artifact_schema` says so of itself:
//! "documentation, not a rule". A scaffolder that tried to validate the logic
//! it just wrote would be a second opinion about a question the design gives
//! exactly one answer to. So the stub *runs* and returns a verdict, and what it
//! decides is wrong on purpose: rejecting everything is the safe direction for
//! a checker nobody has finished writing.
//!
//! The generated stub is not a syntax skeleton. It has the fields its kind's
//! verifier actually reads (see [`crate::verifiers`] and
//! `spec/objective.schema.json`) already wired up, so `proofwork post` accepts
//! it and a submission against it returns a real `reject` -- which means the
//! first thing an author does is change a decision, not debug a spec.

use std::collections::BTreeMap;
use std::fmt;

use crate::canonical::Value;

/// Which of the five verifier kinds the new objective uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Certificate,
    Evaluator,
    Statistical,
    Replay,
    Lean,
}

/// Every kind, in the order [`Kind::name`] spells them.
pub const KINDS: [Kind; 5] = [
    Kind::Certificate,
    Kind::Evaluator,
    Kind::Statistical,
    Kind::Replay,
    Kind::Lean,
];

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Certificate => "certificate",
            Kind::Evaluator => "evaluator",
            Kind::Statistical => "statistical",
            Kind::Replay => "replay",
            Kind::Lean => "lean",
        }
    }

    pub fn parse(name: &str) -> Option<Kind> {
        KINDS.into_iter().find(|kind| kind.name() == name)
    }

    /// The directory a pinned script goes in, matching what `examples/` uses.
    ///
    /// `None` for the two kinds that pin no file of their own: `lean` carries
    /// its statement inline, and `replay` names a command that already exists.
    fn script_dir(self) -> Option<&'static str> {
        match self {
            Kind::Certificate => Some("checkers"),
            Kind::Evaluator => Some("evaluators"),
            Kind::Statistical => Some("statistics"),
            Kind::Replay | Kind::Lean => None,
        }
    }

    /// The function name the verifier calls into.
    fn entrypoint(self) -> Option<&'static str> {
        match self {
            Kind::Certificate => Some("check"),
            Kind::Evaluator => Some("score"),
            Kind::Statistical => Some("statistic"),
            Kind::Replay | Kind::Lean => None,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What the caller chose. Everything not given has a default that produces a
/// postable objective, because a scaffold that needs eight flags before it
/// emits anything is a form, not a shortcut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Directory name, and the stem of the generated script.
    pub name: String,
    pub kind: Kind,
    /// Where the objective directory goes, **relative to the bundle root**.
    ///
    /// The pin inside `objective.json` is resolved against `--root`, so this
    /// path is part of the record, not merely where a file landed. See
    /// [`Plan::objective_path`].
    pub parent: String,
    pub goal: String,
    pub statement: String,
    pub funder: String,
    pub reward: u64,
    /// A worked example artifact, if the author has one. Shapes
    /// `artifact_schema` the way `examples/collatz/objective.json` does.
    pub artifact_example: Option<Value>,
}

impl Request {
    /// A request with every default filled in, for `name` and `kind`.
    pub fn new(name: impl Into<String>, kind: Kind) -> Request {
        let name = name.into();
        Request {
            statement: format!(
                "TODO: state what is being asked, precisely enough that {} is \
                 recognisably a faithful encoding of it.",
                match kind {
                    Kind::Lean => "the theorem below",
                    Kind::Replay => "the pinned command",
                    _ => "the pinned script",
                }
            ),
            goal: format!("GOAL-{name}"),
            funder: String::from("TODO-funder"),
            reward: 0,
            parent: String::from("examples"),
            artifact_example: None,
            name,
            kind,
        }
    }
}

/// What is wrong with a request, before anything is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScaffoldError {
    /// A name that would not be a single directory component.
    BadName { name: String },
    /// A parent that leaves the bundle root, which would make the pin
    /// unresolvable for everyone but the author.
    BadParent { parent: String },
    /// An artifact example that is not a JSON object.
    BadArtifactExample,
}

impl fmt::Display for ScaffoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScaffoldError::BadName { name } => write!(
                f,
                "{name:?} is not usable as a directory name: use letters, digits, \
                 '-' and '_' only"
            ),
            ScaffoldError::BadParent { parent } => write!(
                f,
                "{parent:?} escapes the bundle root; the objective's pin is resolved \
                 against --root, so a path outside it resolves for nobody else"
            ),
            ScaffoldError::BadArtifactExample => {
                write!(f, "--artifact-example must be a JSON object")
            }
        }
    }
}

impl std::error::Error for ScaffoldError {}

/// The files to write, and the command to print afterwards.
///
/// Returned rather than written so the decision and the side effect are
/// separable: everything interesting about this module is testable without a
/// filesystem, and the caller is the one that gets to refuse to overwrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// `(path relative to the bundle root, contents)`, in write order.
    pub files: Vec<(String, String)>,
    /// Where `objective.json` landed, for the `post` line.
    pub objective_path: String,
    /// What still has to be decided before this is worth posting.
    pub todo: Vec<String>,
}

/// Build the file set for `request`.
pub fn plan(request: &Request) -> Result<Plan, ScaffoldError> {
    check_name(&request.name)?;
    check_parent(&request.parent)?;
    if let Some(example) = &request.artifact_example {
        if example.as_object().is_none() {
            return Err(ScaffoldError::BadArtifactExample);
        }
    }

    let dir = join(&request.parent, &request.name);
    let mut files: Vec<(String, String)> = Vec::new();

    // The script first: the objective pins its hash, so it has to exist as
    // text before the record naming it can be built.
    let script = request.kind.script_dir().map(|sub| {
        let path = join(&join(&dir, sub), &format!("{}.py", request.name));
        let body = script_for(request);
        (path, body)
    });
    if let Some((path, body)) = &script {
        files.push((path.clone(), body.clone()));
    }

    let verifier = verifier_block(
        request,
        script
            .as_ref()
            .map(|(path, body)| (path.as_str(), body.as_str())),
    );
    let objective = objective_record(request, verifier);
    let objective_path = join(&dir, "objective.json");
    files.push((objective_path.clone(), pretty(&objective)));

    files.push((join(&dir, "artifact.json"), pretty(&artifact_stub(request))));

    Ok(Plan {
        files,
        objective_path,
        todo: todo_for(request),
    })
}

fn check_name(name: &str) -> Result<(), ScaffoldError> {
    let usable = !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if usable {
        Ok(())
    } else {
        Err(ScaffoldError::BadName {
            name: name.to_string(),
        })
    }
}

/// A parent must stay under the bundle root, and must be relative to it.
///
/// Not a filesystem check -- the directory need not exist yet -- but a check on
/// the *string that ends up in the record*. An absolute path or a `..` makes a
/// pin that resolves on the author's machine and nowhere else, which mints an
/// objective whose every claim comes back `unavailable` forever.
fn check_parent(parent: &str) -> Result<(), ScaffoldError> {
    let bad = parent.starts_with('/')
        || parent.starts_with('\\')
        || parent.split(['/', '\\']).any(|part| part == "..");
    if bad {
        Err(ScaffoldError::BadParent {
            parent: parent.to_string(),
        })
    } else {
        Ok(())
    }
}

fn join(base: &str, leaf: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.is_empty() || base == "." {
        leaf.to_string()
    } else {
        format!("{base}/{leaf}")
    }
}

/// The verifier block, with exactly the fields this kind's verifier reads.
fn verifier_block(request: &Request, script: Option<(&str, &str)>) -> Value {
    let mut fields: Vec<(String, Value)> =
        vec![(String::from("kind"), Value::string(request.kind.name()))];
    let entrypoint = request.kind.entrypoint();
    match request.kind {
        Kind::Certificate => {
            if let Some((path, body)) = script {
                fields.push((String::from("checker"), Value::string(path)));
                fields.push((
                    String::from("checker_sha256"),
                    Value::string(crate::blobs::address(body.as_bytes())),
                ));
            }
        }
        Kind::Evaluator => {
            if let Some((path, body)) = script {
                fields.push((String::from("evaluator"), Value::string(path)));
                fields.push((
                    String::from("evaluator_sha256"),
                    Value::string(crate::blobs::address(body.as_bytes())),
                ));
            }
            // Both required: `spec_threshold` refuses a missing threshold, and
            // `direction` defaults to maximize -- written out anyway, because
            // which way a score is better is the first thing an author changes
            // and a default they cannot see is a default they will not.
            fields.push((String::from("threshold"), Value::Int(1)));
            fields.push((String::from("direction"), Value::string("maximize")));
        }
        Kind::Statistical => {
            if let Some((path, body)) = script {
                fields.push((
                    String::from("statistic"),
                    Value::object([
                        ("path", Value::string(path)),
                        (
                            "sha256",
                            Value::string(crate::blobs::address(body.as_bytes())),
                        ),
                    ]),
                ));
            }
            fields.push((String::from("threshold"), Value::Int(10_000)));
            fields.push((String::from("direction"), Value::string("minimize")));
            // The seed comes from the objective, never the artifact: a
            // submitter who could choose the randomisation could grind seeds
            // until one cleared.
            fields.push((String::from("seed"), Value::Int(1)));
        }
        Kind::Replay => {
            fields.push((
                String::from("command"),
                Value::array([Value::string("python3"), Value::string("TODO-rerun.py")]),
            ));
            fields.push((String::from("cwd"), Value::string(".")));
            // Non-empty, and never a timing or a memory figure: those measure
            // the host rather than the computation, and the verifier refuses
            // them as a spec defect.
            fields.push((
                String::from("reproducible_fields"),
                Value::array([Value::string("result")]),
            ));
            fields.push((String::from("timeout_seconds"), Value::Int(120)));
        }
        Kind::Lean => {
            fields.push((
                String::from("statement"),
                Value::string("theorem TODO_name (a b : Nat) : a + b = b + a"),
            ));
            fields.push((String::from("preamble"), Value::string("")));
            fields.push((String::from("timeout_seconds"), Value::Int(120)));
        }
    }
    if let Some(entrypoint) = entrypoint {
        fields.push((String::from("entrypoint"), Value::string(entrypoint)));
    }
    Value::object(fields)
}

fn objective_record(request: &Request, verifier: Value) -> Value {
    let mut fields: Vec<(String, Value)> = vec![
        (String::from("goal"), Value::string(&request.goal)),
        (String::from("statement"), Value::string(&request.statement)),
        (String::from("verifier"), verifier),
        (
            String::from("reward"),
            Value::Int(i128::from(request.reward)),
        ),
        (String::from("funder"), Value::string(&request.funder)),
        // A placeholder rather than the current clock: this file is edited and
        // reviewed before it is posted, and a timestamp from generation time
        // would claim the objective was created at a moment nobody chose.
        (
            String::from("created_at"),
            Value::string("1970-01-01T00:00:00+00:00"),
        ),
    ];
    if let Some(schema) = artifact_schema(request) {
        fields.push((String::from("artifact_schema"), schema));
    }
    Value::object(fields)
}

/// `artifact_schema` from a worked example, in the shape
/// `examples/collatz/objective.json` uses.
///
/// Types are read off the example's top-level fields and nothing deeper: this
/// is documentation for a submitter who has only the record, and a
/// hand-written hint that happens to be a worked example is more useful than a
/// generated schema that is wrong about a nested shape. Nothing validates an
/// artifact against it -- the pinned verifier is the only gate.
fn artifact_schema(request: &Request) -> Option<Value> {
    let example = request.artifact_example.as_ref()?;
    let map = example.as_object()?;
    let mut properties: Vec<(String, Value)> = Vec::new();
    let mut required: Vec<Value> = Vec::new();
    for (key, value) in map {
        properties.push((
            key.clone(),
            Value::object([("type", Value::string(json_type(value)))]),
        ));
        required.push(Value::string(key));
    }
    Some(Value::object([
        (
            "description",
            Value::string("TODO: what the verifier reads out of an artifact."),
        ),
        ("type", Value::string("object")),
        ("properties", Value::object(properties)),
        ("required", Value::array(required)),
        ("example", example.clone()),
    ]))
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Int(_) => "integer",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// The placeholder artifact, so `score_candidate` has something to be pointed
/// at on the first run.
fn artifact_stub(request: &Request) -> Value {
    if let Some(example) = &request.artifact_example {
        return example.clone();
    }
    match request.kind {
        Kind::Lean => Value::object([(
            "proof",
            Value::string("by TODO -- the tactic block that closes the statement"),
        )]),
        Kind::Statistical => Value::object([(
            "pairs",
            Value::array([Value::array([Value::Int(0), Value::Int(0)])]),
        )]),
        Kind::Replay => Value::object([("result", Value::string("TODO"))]),
        Kind::Certificate | Kind::Evaluator => Value::object([("witness", Value::string("TODO"))]),
    }
}

/// The stub the objective pins.
///
/// It runs and returns a verdict rather than being a syntax skeleton, and the
/// verdict is "no" -- see the module docs for why that direction.
fn script_for(request: &Request) -> String {
    let name = &request.name;
    match request.kind {
        Kind::Certificate => format!(
            r#""""Certificate checker for {name}.

Recompute the property from scratch and trust nothing in the artifact except
the bare witness. How the submitter found it is irrelevant and unverifiable,
which is the point: an unreliable contributor is safe to accept because this
file, not their claim, decides.

`check` returns `(accepted, detail)`. The detail is public verdict evidence, so
write it for somebody deciding whether to build on this result -- and put
nothing in it you would not publish.

TODO: replace the body. It rejects everything, which is the safe direction for
a checker nobody has finished writing.
"""


def check(artifact: dict) -> tuple[bool, str]:
    witness = artifact.get("witness")
    if witness is None:
        return False, "artifact has no 'witness'"
    # TODO: re-derive the property here and return True only when it holds.
    return False, f"checker for {name} is a stub: {{witness!r}} was not checked"
"#
        ),
        Kind::Evaluator => format!(
            r#""""Evaluator for {name}: how good is this artifact?

Returns an **int**, never a float: a score that differs in the last bit across
two nodes is a score that can straddle the threshold, and two honest verifiers
would then disagree about whether the same artifact settled.

An invalid submission scores zero rather than raising. That distinction decides
whether the objective can be attacked by submitting garbage: a raise is
`unavailable`, which settles nothing and can be provoked at will; a zero is a
real verdict about a bad artifact.

TODO: replace the body. It scores everything zero, which under the objective's
`threshold` and `direction` rejects everything.
"""


def score(artifact: dict) -> int:
    candidate = artifact.get("witness")
    if candidate is None:
        return 0
    # TODO: measure the artifact and return an integer score. Scale a
    # fractional quantity into integer units rather than returning a float.
    return 0
"#
        ),
        Kind::Statistical => format!(
            r#""""Pre-registered test statistic for {name}.

Two properties make this usable as a unit of account:

**Pinned before the data exists.** This file's SHA-256 is inside the objective
and the objective's id covers it, so the rejection rule cannot be chosen after
seeing the numbers -- doing that requires posting a different objective, which
has funded nothing.

**Bit-reproducible.** Every node must get the identical integer. That means no
floats anywhere, no `random` module (its stream is not a specification other
implementations are obliged to reproduce -- write the generator out longhand),
and the seed arrives from the objective, never from the artifact: a submitter
who could choose the randomisation could grind seeds until one cleared.

`statistic` returns an int. Scale a probability into parts per million and
round in the direction that makes acceptance harder.

TODO: replace the body. It returns a value no threshold clears.
"""

SCALE = 1_000_000


def statistic(artifact: dict, seed: int) -> int:
    pairs = artifact.get("pairs")
    if not isinstance(pairs, list) or not pairs:
        return SCALE
    # TODO: compute the pre-registered statistic over `pairs`, using `seed` for
    # any randomisation, in integer arithmetic only.
    return SCALE
"#
        ),
        // Neither kind pins a script of its own.
        Kind::Replay | Kind::Lean => String::new(),
    }
}

/// What is left for a human, in the order they will hit it.
fn todo_for(request: &Request) -> Vec<String> {
    let mut todo = Vec::new();
    // Only what is still a placeholder. Listing a decision the author already
    // made on the command line teaches them to skim the list, which is the one
    // thing it cannot afford -- the pin item below is the expensive one.
    if request.statement.starts_with("TODO") {
        todo.push(String::from(
            "statement -- say what is being asked, precisely enough that the verifier is \
             recognisably a faithful encoding of it",
        ));
    }
    if request.funder.starts_with("TODO") {
        todo.push(String::from("funder -- who is paying for this"));
    }
    if request.reward == 0 {
        todo.push(String::from(
            "reward -- an objective with reward 0 is postable and pays nobody",
        ));
    }
    todo.push(String::from(
        "created_at -- the placeholder is 1970; stamp it when you decide to post",
    ));
    match request.kind {
        Kind::Certificate => todo.push(String::from(
            "checkers/*.py -- the stub rejects everything; re-derive the property and \
             re-pin with `proofwork canon` after editing (the hash is part of the id)",
        )),
        Kind::Evaluator => todo.push(String::from(
            "evaluators/*.py and threshold/direction -- the stub scores 0; re-pin after editing",
        )),
        Kind::Statistical => todo.push(String::from(
            "statistics/*.py, threshold and seed -- the stub clears nothing; re-pin after editing",
        )),
        Kind::Replay => todo.push(String::from(
            "command, cwd and reproducible_fields -- the command must print one JSON object, \
             and no declared field may be a timing or a memory figure",
        )),
        // Named `verifier.statement` because the objective has a `statement`
        // too and they are different things: one is prose for a reader, this
        // is the theorem the proof must close.
        Kind::Lean => todo.push(String::from(
            "verifier.statement -- the Lean theorem the proof must close, and a preamble \
             if it needs imports",
        )),
    }
    if request.artifact_example.is_none() {
        todo.push(String::from(
            "artifact.json and artifact_schema -- pass --artifact-example FILE to fill both from \
             a worked example",
        ));
    }
    todo
}

/// Two-space-indented JSON with sorted keys, matching `examples/`.
///
/// Not [`Value::canonical_string`]: that is the consensus encoding, and these
/// are files a person edits. The record's id is computed from the canonical
/// form of what is *parsed back*, so whitespace here changes nothing.
fn pretty(value: &Value) -> String {
    let mut out = String::new();
    write_pretty(&mut out, value, 0);
    out.push('\n');
    out
}

fn write_pretty(out: &mut String, value: &Value, depth: usize) {
    match value {
        Value::Object(map) => {
            write_block(out, map.iter().map(|(k, v)| (Some(k), v)), depth, '{', '}')
        }
        Value::Array(items) => {
            write_block(out, items.iter().map(|item| (None, item)), depth, '[', ']')
        }
        // Scalars have exactly one spelling, and it is the canonical one.
        other => out.push_str(&other.canonical_string()),
    }
}

fn write_block<'a>(
    out: &mut String,
    entries: impl Iterator<Item = (Option<&'a String>, &'a Value)>,
    depth: usize,
    open: char,
    close: char,
) {
    let entries: Vec<(Option<&String>, &Value)> = entries.collect();
    out.push(open);
    if entries.is_empty() {
        out.push(close);
        return;
    }
    let inner = depth.saturating_add(1);
    for (index, (key, value)) in entries.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('\n');
        indent(out, inner);
        if let Some(key) = key {
            out.push_str(&Value::string(key.as_str()).canonical_string());
            out.push_str(": ");
        }
        write_pretty(out, value, inner);
    }
    out.push('\n');
    indent(out, depth);
    out.push(close);
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

/// Round-trip helper for callers that want the objective back as a value.
pub fn parse_objective(text: &str) -> Option<BTreeMap<String, Value>> {
    Value::from_json(text)
        .ok()
        .and_then(|value| value.as_object().cloned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::Objective;
    use crate::schema::validate_objective;

    fn objective_of(plan: &Plan) -> Value {
        let (_, text) = plan
            .files
            .iter()
            .find(|(path, _)| path == &plan.objective_path)
            .expect("the plan writes an objective");
        Value::from_json(text).expect("the generated objective is JSON")
    }

    /// The contract third parties implement against. A scaffold that emitted
    /// something `proofwork post` refuses would be worse than no scaffold.
    #[test]
    fn every_kind_produces_an_objective_the_published_schema_accepts() {
        for kind in KINDS {
            let plan = plan(&Request::new("demo", kind)).expect("plans");
            let value = objective_of(&plan);
            validate_objective(&value)
                .unwrap_or_else(|error| panic!("{kind}: schema refused it: {error}"));
            let objective = Objective::from_value(&value)
                .unwrap_or_else(|error| panic!("{kind}: not a record: {error}"));
            assert_eq!(objective.verifier_kind(), Some(kind.name()));
        }
    }

    /// The pin is part of the objective's id, so a pin that does not match the
    /// file beside it mints a bounty that can never settle.
    #[test]
    fn the_generated_pin_matches_the_generated_script() {
        for kind in [Kind::Certificate, Kind::Evaluator, Kind::Statistical] {
            let plan = plan(&Request::new("demo", kind)).expect("plans");
            let value = objective_of(&plan);
            let verifier = value.get("verifier").expect("a verifier block");
            let (path, declared) = match kind {
                Kind::Certificate => (
                    verifier.get("checker").and_then(Value::as_str).unwrap(),
                    verifier
                        .get("checker_sha256")
                        .and_then(Value::as_str)
                        .unwrap(),
                ),
                Kind::Evaluator => (
                    verifier.get("evaluator").and_then(Value::as_str).unwrap(),
                    verifier
                        .get("evaluator_sha256")
                        .and_then(Value::as_str)
                        .unwrap(),
                ),
                _ => {
                    let statistic = verifier.get("statistic").expect("a statistic block");
                    (
                        statistic.get("path").and_then(Value::as_str).unwrap(),
                        statistic.get("sha256").and_then(Value::as_str).unwrap(),
                    )
                }
            };
            let (_, body) = plan
                .files
                .iter()
                .find(|(candidate, _)| candidate == path)
                .unwrap_or_else(|| panic!("{kind}: the plan writes {path}"));
            assert_eq!(
                declared,
                crate::blobs::address(body.as_bytes()),
                "{kind}: the pin does not match the file it names"
            );
        }
    }

    #[test]
    fn the_script_lands_under_the_objective_directory() {
        let request = Request {
            parent: String::from("examples/nested"),
            ..Request::new("widget", Kind::Certificate)
        };
        let plan = plan(&request).expect("plans");
        assert_eq!(plan.objective_path, "examples/nested/widget/objective.json");
        assert!(plan
            .files
            .iter()
            .any(|(path, _)| path == "examples/nested/widget/checkers/widget.py"));
    }

    #[test]
    fn a_worked_example_fills_both_the_schema_and_the_placeholder_artifact() {
        let example = Value::from_json(r#"{"n": 27, "note": "hi"}"#).expect("json");
        let request = Request {
            artifact_example: Some(example.clone()),
            ..Request::new("demo", Kind::Certificate)
        };
        let plan = plan(&request).expect("plans");
        let value = objective_of(&plan);
        let schema = value.get("artifact_schema").expect("a schema hint");
        assert_eq!(schema.get("example"), Some(&example));
        assert_eq!(
            schema
                .get("properties")
                .and_then(|p| p.get("n"))
                .and_then(|n| n.get("type"))
                .and_then(Value::as_str),
            Some("integer")
        );
        let (_, artifact) = plan
            .files
            .iter()
            .find(|(path, _)| path.ends_with("artifact.json"))
            .expect("a placeholder artifact");
        assert_eq!(Value::from_json(artifact).expect("json"), example);
    }

    /// Absent, not null: a field written as `null` is a different objective id
    /// from one that omits it.
    #[test]
    fn no_artifact_example_omits_the_schema_rather_than_nulling_it() {
        let plan = plan(&Request::new("demo", Kind::Certificate)).expect("plans");
        let value = objective_of(&plan);
        assert!(value.get("artifact_schema").is_none());
    }

    #[test]
    fn a_path_that_would_not_resolve_for_anyone_else_is_refused() {
        for parent in ["/tmp", "../outside", "examples/../.."] {
            let request = Request {
                parent: String::from(parent),
                ..Request::new("demo", Kind::Certificate)
            };
            assert!(
                matches!(plan(&request), Err(ScaffoldError::BadParent { .. })),
                "{parent} was accepted"
            );
        }
        for name in ["", ".", "..", "a/b", "a b"] {
            let request = Request::new(name, Kind::Certificate);
            assert!(
                matches!(plan(&request), Err(ScaffoldError::BadName { .. })),
                "{name:?} was accepted"
            );
        }
    }

    #[test]
    fn an_artifact_example_that_is_not_an_object_is_refused() {
        let request = Request {
            artifact_example: Some(Value::from_json("[1, 2]").expect("json")),
            ..Request::new("demo", Kind::Certificate)
        };
        assert_eq!(plan(&request), Err(ScaffoldError::BadArtifactExample));
    }

    /// Replay's verifier refuses a timing or a memory figure as a spec defect,
    /// so a stub that suggested one would generate an objective that can never
    /// settle.
    #[test]
    fn the_replay_stub_declares_no_machine_dependent_field() {
        let plan = plan(&Request::new("demo", Kind::Replay)).expect("plans");
        let value = objective_of(&plan);
        let fields = value
            .get("verifier")
            .and_then(|v| v.get("reproducible_fields"))
            .and_then(Value::as_array)
            .expect("declared fields");
        assert!(!fields.is_empty());
        for field in fields {
            let name = field.as_str().expect("a string");
            assert!(
                !["seconds", "elapsed", "duration", "memory", "rss", "time"]
                    .iter()
                    .any(|bad| name.contains(bad)),
                "{name} measures the host, not the computation"
            );
        }
    }

    #[test]
    fn the_generated_json_reparses_to_the_same_value() {
        for kind in KINDS {
            let plan = plan(&Request::new("demo", kind)).expect("plans");
            for (path, text) in &plan.files {
                if path.ends_with(".json") {
                    Value::from_json(text)
                        .unwrap_or_else(|error| panic!("{path}: not JSON: {error}"));
                }
            }
        }
    }

    #[test]
    fn the_todo_list_names_what_is_left_and_not_what_was_already_decided() {
        let blank = plan(&Request::new("demo", Kind::Lean)).expect("plans");
        assert!(blank.todo.iter().any(|line| line.starts_with("reward")));
        assert!(blank.todo.iter().any(|line| line.starts_with("funder")));
        assert!(blank.todo.iter().any(|line| line.starts_with("statement")));

        let decided = plan(&Request {
            statement: String::from("Exhibit a widget of order at least 12."),
            funder: String::from("treasury"),
            reward: 5000,
            ..Request::new("demo", Kind::Lean)
        })
        .expect("plans");
        assert!(!decided.todo.iter().any(|line| line.starts_with("reward")));
        assert!(!decided.todo.iter().any(|line| line.starts_with("funder")));
        assert!(!decided
            .todo
            .iter()
            .any(|line| line.starts_with("statement")));
        // The one that costs money to get wrong stays, always.
        assert!(decided.todo.iter().any(|line| line.contains("created_at")));
    }
}
