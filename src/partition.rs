//! Work assignment without a coordinator.
//!
//! The reflex when thousands of nodes must avoid duplicating work is to build a
//! dispatcher: a server that hands out work units and tracks who holds what.
//! BOINC does this and it is the right call there, because BOINC's participants
//! are not adversarial. Here they are, and a dispatcher is a single point of
//! censorship, a liveness bottleneck, and a thing that must itself be
//! replicated and agreed on.
//!
//! None of that is necessary, because **work assignment does not need
//! agreement**. Two nodes searching the same region is not an error -- it is a
//! little wasted compute, self-correcting the moment either publishes. So
//! assignment can be a pure function every node evaluates locally:
//!
//! ```text
//! partition = H(beacon(epoch) ‖ node_id ‖ objective_id) mod n
//! ```
//!
//! No messages, no locks, no reservations, no coordinator. Every node computes
//! its own assignment and can compute anyone else's, which is what makes "did
//! you actually search your region?" a checkable question later.
//!
//! # Why the beacon
//!
//! Without an epoch-varying input the mapping is fixed forever: a node
//! permanently owns a region, and an adversary who wants a region left
//! unsearched simply generates identities until one lands there and then does
//! nothing. Mixing in a per-epoch beacon rotates every assignment, so squatting
//! a region costs a fresh grinding effort each epoch and blocking one
//! indefinitely becomes impractical.
//!
//! The beacon must be **unpredictable before the epoch and verifiable after**.
//! This module derives it from a chain of ledger heads, which is honest about
//! what it provides: any value the sequencer could have chosen freely is a
//! value the sequencer could have ground to place itself favourably. At Stage 0
//! the sequencer is trusted not to; at Stage 2 this must become a real
//! randomness beacon (a VDF or a threshold signature) and this paragraph should
//! stop making excuses for it.
//!
//! # Notes for the port
//!
//! Nothing here touches money, but two Rust-specific hazards do apply and are
//! handled rather than hoped away:
//!
//! - `partitions == 0` is a division by zero. Python raises; a Rust `%` would
//!   panic, and a panic in assignment is a remote crash triggered by a number
//!   any peer can put in a record. It is an error value instead --
//!   [`PartitionError::ZeroPartitions`].
//! - [`Assignment`] has public fields (it is data a caller reads), so a struct
//!   literal can produce a `partition` outside `0..partitions`. Python's
//!   bignums make that merely nonsensical; here `partition * step` would
//!   overflow `u64` and, with `overflow-checks = true` in this crate's release
//!   profile, abort. [`Assignment::share`] therefore computes in `u128` and
//!   clamps -- a malformed assignment covers nothing instead of crashing or
//!   silently wrapping into somebody else's region.

use std::fmt;

use crate::hex;
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Length of one assignment epoch, in seconds.
///
/// Ten minutes: long enough that a node can finish a useful chunk of search
/// inside one assignment, short enough that a squatted region is released again
/// soon. Passed explicitly at every call site rather than defaulted inside
/// [`epoch_of`]: an epoch length that a caller can forget to supply is one that
/// silently differs between two nodes, and the length is exactly the kind of
/// parameter a consensus split hides in.
pub const EPOCH_SECONDS: u64 = 600;

/// Size of the assignment space: the unit interval scaled to `2^32`.
///
/// Item positions are the first four bytes of an item's SHA-256, so the space
/// is exactly the range of a `u32`. Slices are half-open `[lo, hi)` sub-ranges
/// of it and are carried as `u64` because the exclusive upper end of the last
/// slice is `2^32` itself, which a `u32` cannot hold.
pub const SPACE: u64 = 1 << 32;

/// An assignment could not be computed or is not well formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionError {
    /// `partitions` was zero. There is no slice to assign and `x mod 0` is not
    /// a number; the reference implementation raises `ValueError` here.
    ZeroPartitions,
    /// `partition` is not a valid index into `partitions` slices. The reference
    /// implementation never constructs one, but this crate exposes
    /// [`Assignment`]'s fields, so the constructor checks what the struct
    /// literal cannot.
    PartitionOutOfRange { partition: u32, partitions: u32 },
    /// The beacon could not be used as an HMAC key. HMAC accepts keys of any
    /// length -- long ones are hashed down, short ones zero-padded -- so this
    /// is unreachable for every `&str`. It is reported rather than unwrapped
    /// because assignment runs on peer-supplied input and must not be a way to
    /// halt a node.
    UnusableBeacon,
    /// A reduced value did not fit the type that holds it. Also unreachable
    /// (`x mod n < n <= u32::MAX`), and also reported rather than asserted, for
    /// the same reason: nothing in this module is worth a panic.
    Unrepresentable,
}

impl fmt::Display for PartitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PartitionError::ZeroPartitions => {
                f.write_str("partitions must be positive; there is nothing to assign")
            }
            PartitionError::PartitionOutOfRange {
                partition,
                partitions,
            } => write!(
                f,
                "partition {partition} is outside the range 0..{partitions}"
            ),
            PartitionError::UnusableBeacon => {
                f.write_str("epoch beacon could not be used as an HMAC key")
            }
            PartitionError::Unrepresentable => {
                f.write_str("assignment value did not fit its representation")
            }
        }
    }
}

impl std::error::Error for PartitionError {}

/// Per-epoch randomness. `anchor` is a ledger head or equivalent commitment.
///
/// Returns **plain lowercase hex with no `sha256:` prefix**, unlike
/// [`crate::canonical::digest_bytes`]. That is not an oversight: the returned
/// string is fed to [`assign`] as HMAC key material, byte for byte, so its
/// spelling is part of the wire format. Prefixing it would change every
/// assignment in the network.
pub fn beacon(epoch: u64, anchor: &str) -> String {
    hex::encode(&Sha256::digest(format!("{epoch}:{anchor}").as_bytes()))
}

/// Which slice of the search space this node takes. Pure, local, checkable.
///
/// The key is the beacon's **hex text**, not the 32 bytes it encodes -- the
/// reference implementation keys the MAC with `epoch_beacon.encode()`, and any
/// implementation that decodes the hex first computes different assignments for
/// every node in the network. The message is `"{node_id}|{objective_id}"`; the
/// separator keeps `("ab", "c")` and `("a", "bc")` from colliding.
///
/// The draw is the first eight MAC bytes read big-endian, reduced modulo
/// `partitions`. The modulo bias is real and irrelevant: it is on the order of
/// `partitions / 2^64`, and assignment only has to spread nodes out, not be
/// uniform to the last bit. Anyone can recompute this for any node, which is
/// what turns "search your own region" into an auditable claim.
pub fn assign(
    node_id: &str,
    objective_id: &str,
    epoch_beacon: &str,
    partitions: u32,
) -> Result<u32, PartitionError> {
    if partitions == 0 {
        return Err(PartitionError::ZeroPartitions);
    }
    let mut mac = HmacSha256::new_from_slice(epoch_beacon.as_bytes())
        .map_err(|_| PartitionError::UnusableBeacon)?;
    mac.update(format!("{node_id}|{objective_id}").as_bytes());
    let tag = mac.finalize().into_bytes();

    // `int.from_bytes(mac[:8], "big")`, written as a fold so there is no
    // slicing to get out of bounds and no fixed-length array to mis-size.
    let mut draw: u64 = 0;
    for byte in tag.iter().take(8) {
        draw = (draw << 8) | u64::from(*byte);
    }

    let partition = draw % u64::from(partitions);
    // `partition < partitions <= u32::MAX`, so this always fits. `try_from`
    // states that as a check rather than a comment: if the reasoning above ever
    // stops holding, the result is a refused assignment, not a truncated one
    // that silently claims another node's region.
    u32::try_from(partition).map_err(|_| PartitionError::Unrepresentable)
}

/// Which epoch a timestamp falls in: floor division, so epochs are contiguous
/// and monotone in time.
///
/// Pass [`EPOCH_SECONDS`] for the network default. A zero `epoch_seconds` has
/// no meaningful answer -- Python raises `ZeroDivisionError` -- but this
/// function's result feeds [`beacon`], so it returns epoch `0` rather than
/// panicking a node over a nonsense parameter. A caller that passes `0` has a
/// bug either way; it should not be a crash.
pub fn epoch_of(timestamp_seconds: u64, epoch_seconds: u64) -> u64 {
    timestamp_seconds.checked_div(epoch_seconds).unwrap_or(0)
}

/// Overrides [`EPOCH_SECONDS`] for a local demo. Never set this in production.
pub const EPOCH_SECONDS_ENV: &str = "PROOFWORK_EPOCH_SECONDS";

/// The epoch length in force for this process.
///
/// [`EPOCH_SECONDS`] is ten minutes, which makes the commit-in-N/reveal-in-N+1
/// rule impossible to demonstrate in a shell script that has to finish. The
/// override exists for exactly that and for nothing else.
///
/// Two nodes with different settings disagree about which epoch a record is in
/// and therefore about which reveals were legal — so this is a *policy*
/// parameter, not a format one. It changes no canonical bytes: nothing derived
/// from it enters a record, and every id in the log is identical whatever it is
/// set to. A malformed or zero value falls back to the default rather than
/// producing an epoch length of nothing.
pub fn epoch_seconds() -> u64 {
    match std::env::var(EPOCH_SECONDS_ENV) {
        Ok(text) => match text.trim().parse::<u64>() {
            Ok(seconds) if seconds > 0 => seconds,
            _ => EPOCH_SECONDS,
        },
        Err(_) => EPOCH_SECONDS,
    }
}

/// The order acceptable reveals settle in, inside one reveal epoch.
///
/// `H(beacon(epoch, anchor) ‖ key)`, ascending. Append order is the sequencer's
/// to choose, and on a progressive objective the order two improvements settle
/// in decides which of them is paid for the whole span and which is paid for
/// the remainder — so leaving settlement order to the sequencer is leaving them
/// a lever on other people's money. Sorting by a value derived from a beacon
/// fixed *before the epoch opened* takes the lever away: the operator can still
/// choose the anchor, but must do so before knowing who will reveal.
///
/// # `key` must be fixed before the anchor is public
///
/// The anchor is the log head at the start of the reveal epoch, so by reveal
/// time every submitter can compute it. Any part of `key` a submitter can still
/// choose at that point is a part they can grind until their rank comes out
/// first, and the rule buys nothing against them.
///
/// Callers therefore pass the **commitment hash**, not the claim id. A claim id
/// covers `created_at` and `cites`, neither of which the commitment binds and
/// neither of which anything checks against the reveal — a submitter could try
/// timestamps until one sorted first. The commitment hash covers exactly the
/// fields the commitment froze an epoch earlier, when the anchor did not exist
/// yet. See [`crate::node::Node::settle_due`] for the residual gap.
///
/// Returned as hex so the ordering is a plain lexicographic string compare that
/// any implementation reproduces, and so an auditor can print it.
pub fn settlement_rank(epoch: u64, anchor: &str, key: &str) -> String {
    hex::encode(&Sha256::digest(
        format!("{}{key}", beacon(epoch, anchor)).as_bytes(),
    ))
}

/// One node's claim on one objective for one epoch.
///
/// Immutable by construction in the reference implementation (a frozen
/// dataclass) and treated as immutable here: build it with [`Assignment::new`]
/// or [`assignment_for`], read it, do not mutate it. The fields stay public
/// because callers legitimately read all five -- to display an assignment, to
/// recompute a peer's, or to record it -- and hiding them behind five getters
/// would buy nothing that `new`'s validation does not already buy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Assignment {
    pub node_id: String,
    pub objective_id: String,
    pub epoch: u64,
    pub partition: u32,
    pub partitions: u32,
}

impl Assignment {
    /// Build a validated assignment.
    ///
    /// Checks the two invariants [`share`](Assignment::share) depends on:
    /// `partitions >= 1` and `partition < partitions`. Nothing forces a caller
    /// through here -- the fields are public -- so `share` still guards itself;
    /// this constructor exists so that the common path fails at construction,
    /// where the error is attributable, rather than silently covering nothing
    /// later.
    pub fn new(
        node_id: impl Into<String>,
        objective_id: impl Into<String>,
        epoch: u64,
        partition: u32,
        partitions: u32,
    ) -> Result<Assignment, PartitionError> {
        if partitions == 0 {
            return Err(PartitionError::ZeroPartitions);
        }
        if partition >= partitions {
            return Err(PartitionError::PartitionOutOfRange {
                partition,
                partitions,
            });
        }
        Ok(Assignment {
            node_id: node_id.into(),
            objective_id: objective_id.into(),
            epoch,
            partition,
            partitions,
        })
    }

    /// The half-open slice `[lo, hi)` of the unit interval scaled to [`SPACE`].
    ///
    /// `step = 2^32 / partitions` truncates, so `partitions * step` is usually
    /// short of `2^32`. The **last** partition therefore absorbs the remainder
    /// and ends exactly at `2^32`. That is what makes the slices tile the space
    /// with no gaps and no overlaps, and both halves of that matter: a gap
    /// leaves items nobody is assigned to search, an overlap makes two nodes
    /// provably responsible for the same item and breaks the "did you search
    /// your region?" check.
    ///
    /// Malformed assignments (reachable only through the public fields) are
    /// answered with an empty range rather than a panic or a wrapped one. Empty
    /// is the fail-closed direction: a broken assignment searches nothing,
    /// instead of claiming the whole space or a region that belongs to someone
    /// else.
    pub fn share(&self) -> (u64, u64) {
        let step = match SPACE.checked_div(u64::from(self.partitions)) {
            Some(step) => step,
            // `partitions == 0`: no slice exists, so the empty range.
            None => return (0, 0),
        };
        // `partitions >= 1` here, so the subtraction is exact.
        let last = self.partitions.saturating_sub(1);
        // u128 throughout: with a malformed `partition` near `u32::MAX` and a
        // `step` of `2^32`, both the product and `lo + step` exceed `u64::MAX`.
        // For any well-formed assignment every value below is at most `2^32`
        // and the clamping is a no-op, so this agrees with the reference
        // implementation exactly where the reference implementation is defined.
        let lo = u128::from(self.partition).saturating_mul(u128::from(step));
        let hi = if self.partition == last {
            u128::from(SPACE)
        } else {
            lo.saturating_add(u128::from(step))
        };
        (clamp_to_space(lo), clamp_to_space(hi))
    }

    /// Does `item_id` fall in this node's slice?
    ///
    /// Lets a node filter a candidate stream down to its own region, and lets
    /// anyone else check that a submitted result came from the region the
    /// submitter was assigned. Because [`assign`] is a pure function of public
    /// inputs, the second use needs no cooperation from the submitter.
    pub fn covers(&self, item_id: &str) -> bool {
        let (lo, hi) = self.share();
        let value = position(item_id);
        lo <= value && value < hi
    }
}

/// Where an item sits in the space: the first four bytes of its SHA-256, read
/// big-endian.
///
/// This is `int(sha256(item).hexdigest()[:8], 16)` in the reference
/// implementation -- eight hex characters are four bytes, so the two agree
/// byte for byte. Only the hash's position matters, not its content, which is
/// why any item with a stable identifier can be partitioned this way.
fn position(item_id: &str) -> u64 {
    let digest = Sha256::digest(item_id.as_bytes());
    let mut value: u64 = 0;
    for byte in digest.iter().take(4) {
        value = (value << 8) | u64::from(*byte);
    }
    value
}

/// Clamp a `u128` position to the assignment space, saturating at [`SPACE`].
///
/// Values above `2^32` only arise from malformed assignments; pinning them to
/// the top of the space turns them into empty slices, which cover nothing.
fn clamp_to_space(value: u128) -> u64 {
    let bounded = value.min(u128::from(SPACE));
    match u64::try_from(bounded) {
        Ok(value) => value,
        // Unreachable: `bounded <= 2^32`.
        Err(_) => SPACE,
    }
}

/// The assignment a node holds for an objective in a given epoch.
///
/// The one call a node actually makes: derive the epoch beacon from the anchor,
/// draw a partition, and package it with the inputs that produced it so the
/// result carries its own provenance.
pub fn assignment_for(
    node_id: &str,
    objective_id: &str,
    epoch: u64,
    anchor: &str,
    partitions: u32,
) -> Result<Assignment, PartitionError> {
    let partition = assign(node_id, objective_id, &beacon(epoch, anchor), partitions)?;
    Assignment::new(node_id, objective_id, epoch, partition, partitions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    // Beacons from the "partition" vectors in conformance/vectors.json.
    const BEACON_E0_ANCHOR: &str =
        "9de02baf354f5febe994ef9a2cc33459a670db2774a9e39e87ba26143b4a157c";
    const BEACON_E1_ANCHOR: &str =
        "e0dcc9fe12107126e483bedee84959f6dc16673c19245d67e0c33d1e8ba131ba";
    const BEACON_E42_ANCHOR: &str =
        "64e64e8b52a0bbb0e36273551c75084ab5f64601fec998eaf9b1eab9dd7a13f7";
    const ABAB: &str = "sha256:abababababababababababababababababababababababababababababababab";
    const BEACON_E1000000_ABAB: &str =
        "8d87e6961620381d18a76abd9b05e3690a51bd8369ef1ac3711bbda6d9f86d63";

    fn assigned(node: &str, partitions: u32) -> u32 {
        assign(node, "obj", BEACON_E0_ANCHOR, partitions).expect("partitions are positive")
    }

    #[test]
    fn beacon_matches_conformance_vectors() {
        assert_eq!(beacon(0, "anchor"), BEACON_E0_ANCHOR);
        assert_eq!(beacon(1, "anchor"), BEACON_E1_ANCHOR);
        assert_eq!(beacon(42, "anchor"), BEACON_E42_ANCHOR);
        assert_eq!(beacon(1_000_000, ABAB), BEACON_E1000000_ABAB);
    }

    #[test]
    fn beacon_is_bare_hex_not_a_prefixed_digest() {
        // The beacon is HMAC key material, so its spelling is consensus-visible.
        let value = beacon(0, "anchor");
        assert_eq!(value.len(), 64);
        assert!(!value.starts_with("sha256:"));
        assert!(value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn beacon_changes_with_anchor_and_epoch() {
        assert_ne!(beacon(1, "a"), beacon(1, "b"));
        assert_ne!(beacon(1, "a"), beacon(2, "a"));
    }

    #[test]
    fn assign_matches_conformance_vectors() {
        // (node_id, partitions, expected partition), epoch 0, anchor "anchor".
        let cases: [(&str, u32, u32); 22] = [
            ("node-0", 1, 0),
            ("node-0", 4, 2),
            ("node-0", 16, 14),
            ("node-0", 1000, 534),
            ("node-1", 1, 0),
            ("node-1", 4, 3),
            ("node-1", 16, 11),
            ("node-1", 1000, 635),
            ("node-2", 1, 0),
            ("node-2", 4, 1),
            ("node-2", 16, 1),
            ("node-2", 1000, 681),
            ("node-3", 1, 0),
            ("node-3", 4, 2),
            ("node-3", 16, 2),
            ("node-3", 1000, 786),
            ("node-4", 4, 1),
            ("node-4", 16, 5),
            ("node-4", 1000, 117),
            ("node-5", 4, 2),
            ("node-5", 16, 14),
            ("node-5", 1000, 462),
        ];
        for (node, partitions, expected) in cases {
            assert_eq!(assigned(node, partitions), expected, "{node}/{partitions}");
        }
        assert_eq!(assign("node-3", "obj", BEACON_E1000000_ABAB, 1000), Ok(406));
    }

    #[test]
    fn draw_is_the_first_eight_mac_bytes_big_endian() {
        // HMAC(key = beacon(0, "anchor"), msg = "node-0|obj") starts
        // 849369f3adfa744e, i.e. 9553095729899795534 big-endian. Reducing by
        // u32::MAX exposes the full draw rather than just its low bits, which
        // pins both the byte count and the byte order.
        assert_eq!(assigned("node-0", u32::MAX), 848_158_274);
        assert_eq!(
            9_553_095_729_899_795_534_u64 % u64::from(u32::MAX),
            848_158_274
        );
    }

    #[test]
    fn zero_partitions_is_an_error_not_a_division_by_zero() {
        assert_eq!(
            assign("n", "o", BEACON_E0_ANCHOR, 0),
            Err(PartitionError::ZeroPartitions)
        );
        assert_eq!(
            assignment_for("n", "o", 1, "anchor", 0),
            Err(PartitionError::ZeroPartitions)
        );
        assert_eq!(
            Assignment::new("n", "o", 1, 0, 0),
            Err(PartitionError::ZeroPartitions)
        );
    }

    #[test]
    fn assignment_is_deterministic() {
        let b = beacon(7, "anchor");
        assert_eq!(
            assign("node-a", "obj", &b, 16),
            assign("node-a", "obj", &b, 16)
        );
    }

    #[test]
    fn different_nodes_get_different_partitions() {
        let b = beacon(7, "anchor");
        let seen: HashSet<u32> = (0..200)
            .filter_map(|i| assign(&format!("node-{i}"), "obj", &b, 16).ok())
            .collect();
        assert!(seen.len() > 8, "assignment is not spreading nodes out");
    }

    #[test]
    fn assignment_rotates_between_epochs() {
        // Without rotation a node owns a region forever, so an adversary grinds
        // one identity into a region and starves it indefinitely.
        let moved = (0..100)
            .filter(|e| {
                assign("node-a", "obj", &beacon(*e, "anchor"), 32)
                    != assign("node-a", "obj", &beacon(e + 1, "anchor"), 32)
            })
            .count();
        assert!(moved > 90, "only {moved} of 100 epoch boundaries moved");
    }

    #[test]
    fn assignment_differs_across_objectives() {
        let b = beacon(3, "anchor");
        let seen: HashSet<u32> = (0..100)
            .filter_map(|i| assign("node-a", &format!("obj-{i}"), &b, 32).ok())
            .collect();
        assert!(seen.len() > 8);
    }

    #[test]
    fn distribution_is_roughly_uniform() {
        let b = beacon(1, "anchor");
        let partitions = 8usize;
        let mut counts = vec![0usize; partitions];
        for i in 0..8000 {
            let p = assign(&format!("node-{i}"), "obj", &b, 8).expect("positive");
            if let Some(slot) = counts.get_mut(p as usize) {
                *slot += 1;
            }
        }
        let expected = 8000.0 / partitions as f64;
        for count in &counts {
            let c = *count as f64;
            assert!(
                c > 0.85 * expected && c < 1.15 * expected,
                "skewed distribution: {counts:?}"
            );
        }
    }

    #[test]
    fn shares_tile_the_space_without_gaps_or_overlap() {
        for partitions in [1u32, 2, 3, 7, 16, 1000, 4096] {
            let mut spans: Vec<(u64, u64)> = (0..partitions)
                .filter_map(|p| Assignment::new("n", "obj", 1, p, partitions).ok())
                .map(|a| a.share())
                .collect();
            spans.sort();
            assert_eq!(spans.len(), partitions as usize);
            assert_eq!(spans.first().map(|s| s.0), Some(0));
            assert_eq!(spans.last().map(|s| s.1), Some(SPACE));
            for pair in spans.windows(2) {
                if let [(_, hi), (lo, _)] = pair {
                    assert_eq!(hi, lo, "partitions must tile the space exactly");
                }
            }
        }
    }

    #[test]
    fn last_partition_absorbs_the_truncation_remainder() {
        // 2^32 / 7 = 613566756 with 4 left over; the last slice is wider.
        let step = SPACE / 7;
        let sixth = Assignment::new("n", "obj", 1, 5, 7).expect("valid");
        let last = Assignment::new("n", "obj", 1, 6, 7).expect("valid");
        assert_eq!(sixth.share(), (5 * step, 6 * step));
        assert_eq!(last.share(), (6 * step, SPACE));
        assert!(last.share().1 - last.share().0 > step);
    }

    #[test]
    fn single_partition_owns_the_whole_space() {
        let only = Assignment::new("n", "obj", 1, 0, 1).expect("valid");
        assert_eq!(only.share(), (0, SPACE));
        assert!(only.covers("item-0"));
        assert!(only.covers("anything at all"));
    }

    #[test]
    fn position_matches_the_reference_hash_extraction() {
        // sha256("item-0") begins 69b65bbe -> 1773558718, just below the
        // midpoint 2^31, so it lands in the lower half.
        assert_eq!(position("item-0"), 1_773_558_718);
        assert_eq!(position("item-1"), 1_502_645_749);
        assert_eq!(position("proofwork"), 1_115_412_704);

        let lower = Assignment::new("n", "obj", 1, 0, 2).expect("valid");
        let upper = Assignment::new("n", "obj", 1, 1, 2).expect("valid");
        assert_eq!(lower.share(), (0, SPACE / 2));
        assert_eq!(upper.share(), (SPACE / 2, SPACE));
        assert!(lower.covers("item-0"));
        assert!(!upper.covers("item-0"));
    }

    #[test]
    fn covers_partitions_items_exactly_once() {
        let partitions = 4u32;
        let mut by_partition: HashMap<u32, Assignment> = HashMap::new();
        for i in 0..400 {
            let a = assignment_for(&format!("n{i}"), "obj", 1, "anchor", partitions)
                .expect("positive partitions");
            by_partition.insert(a.partition, a);
        }
        assert_eq!(by_partition.len(), partitions as usize);
        for i in 0..300 {
            let item = format!("item-{i}");
            let owners = by_partition.values().filter(|a| a.covers(&item)).count();
            assert_eq!(owners, 1, "{item} owned by {owners} partitions");
        }
    }

    #[test]
    fn malformed_assignments_cover_nothing_instead_of_overflowing() {
        // Reachable only through the public fields. In Python these are merely
        // nonsensical; in Rust `partition * step` would overflow u64 and abort
        // under this crate's release overflow checks.
        let no_partitions = Assignment {
            node_id: "n".into(),
            objective_id: "obj".into(),
            epoch: 1,
            partition: 0,
            partitions: 0,
        };
        assert_eq!(no_partitions.share(), (0, 0));
        assert!(!no_partitions.covers("item-0"));

        let past_the_end = Assignment {
            node_id: "n".into(),
            objective_id: "obj".into(),
            epoch: 1,
            partition: u32::MAX,
            partitions: 1,
        };
        assert_eq!(past_the_end.share(), (SPACE, SPACE));
        assert!(!past_the_end.covers("item-0"));

        let just_past = Assignment {
            node_id: "n".into(),
            objective_id: "obj".into(),
            epoch: 1,
            partition: 5,
            partitions: 4,
        };
        let (lo, hi) = just_past.share();
        assert!(lo <= hi && hi <= SPACE);
        assert!(!just_past.covers("item-0"));
    }

    #[test]
    fn share_never_exceeds_the_space_for_extreme_partition_counts() {
        for partitions in [u32::MAX, u32::MAX - 1, 1 << 31] {
            let first = Assignment::new("n", "obj", 1, 0, partitions).expect("valid");
            let last = Assignment::new("n", "obj", 1, partitions - 1, partitions).expect("valid");
            assert_eq!(first.share().0, 0);
            assert_eq!(last.share().1, SPACE);
            assert!(first.share().1 <= SPACE);
        }
    }

    #[test]
    fn assignment_new_rejects_out_of_range_partitions() {
        assert_eq!(
            Assignment::new("n", "o", 1, 4, 4),
            Err(PartitionError::PartitionOutOfRange {
                partition: 4,
                partitions: 4
            })
        );
        assert!(Assignment::new("n", "o", 1, 3, 4).is_ok());
    }

    #[test]
    fn assignment_for_packages_the_draw_with_its_inputs() {
        let a = assignment_for("n0", "obj", 1, "anchor", 7).expect("positive");
        assert_eq!(a.node_id, "n0");
        assert_eq!(a.objective_id, "obj");
        assert_eq!(a.epoch, 1);
        assert_eq!(a.partitions, 7);
        assert_eq!(
            a.partition,
            assign("n0", "obj", &beacon(1, "anchor"), 7).expect("positive")
        );
        // Matches the reference implementation's assignment_for("n0", ...).
        assert_eq!(a.partition, 3);
        assert_eq!(a.share(), (1_840_700_268, 2_454_267_024));
    }

    #[test]
    fn epoch_of_is_monotone_and_total() {
        assert_eq!(epoch_of(0, 600), 0);
        assert_eq!(epoch_of(599, 600), 0);
        assert_eq!(epoch_of(600, 600), 1);
        assert_eq!(epoch_of(u64::MAX, EPOCH_SECONDS), u64::MAX / EPOCH_SECONDS);
        // A zero-length epoch is nonsense, but not a crash.
        assert_eq!(epoch_of(12_345, 0), 0);
    }

    #[test]
    fn settlement_rank_depends_on_every_input() {
        let base = settlement_rank(7, "anchor", "claim:a");
        assert_ne!(base, settlement_rank(8, "anchor", "claim:a"));
        assert_ne!(base, settlement_rank(7, "other", "claim:a"));
        assert_ne!(base, settlement_rank(7, "anchor", "claim:b"));
        assert_eq!(base.len(), 64);
    }

    #[test]
    fn settlement_rank_is_the_hash_of_the_beacon_and_the_id() {
        let expected = crate::hex::encode(&Sha256::digest(
            format!("{}{}", beacon(3, "head"), "claim:x").as_bytes(),
        ));
        assert_eq!(settlement_rank(3, "head", "claim:x"), expected);
    }
}
