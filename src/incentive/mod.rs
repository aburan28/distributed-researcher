//! Why anyone would run a node, and how to check the answer rather than assert it.
//!
//! The rest of this crate pays *submitters*. An objective is funded, an artifact
//! verifies, escrow releases, and citation flow pays the claims it was built on.
//! Nothing in it pays the machines that re-run the verifiers, hold the log,
//! serve it to a stranger who wants to audit it, or custody the Shamir shares
//! that let a sealed submission be opened without its author. Every one of those
//! is a **public good**: the operator bears the whole cost and captures a
//! vanishing slice of the benefit, so the dominant move is to let somebody else
//! do it. When everybody plays the dominant move, "anyone can independently
//! re-derive every result" -- the one property Stage 0 claims -- becomes a
//! sentence in a README rather than a fact about the world.
//!
//! This module is the harness for fixing that: a mechanism, and the tools to
//! evaluate it.
//!
//! # The three services and their asymmetry
//!
//! | service | ground truth held by | so the fix is |
//! |---|---|---|
//! | **availability** -- store the log, answer for it | the protocol: a Merkle root ([`crate::canonical::merkle_root`]) | sample it. A node that cannot answer did not store it |
//! | **custody** -- hold a Shamir share, publish at epoch end ([`crate::sealed`]) | the protocol: shares are committed in advance | attribute it. A share that never appears names its holder |
//! | **verification** -- re-run pinned verifiers ([`crate::verifiers`]) | *nobody* | this is the hard one |
//!
//! Two of the three are easy, and for the same reason: the protocol already
//! knows the right answer, so a node that fails a challenge has proved something
//! about itself. Verification has no such oracle. The whole point of
//! re-verifying is that nobody yet knows whether the artifact is good, so a node
//! that says "accept" without running anything is indistinguishable from a node
//! that ran everything -- and it is cheaper.
//!
//! That is the **verifier's dilemma**, and its bad news is structural rather
//! than quantitative. Punish a node for accepting an artifact that somebody else
//! later proves invalid, and "everybody rubber-stamps" is a Nash equilibrium at
//! *any* penalty: if nobody checks, nobody is caught, so no penalty ever fires.
//! Raising the slash does not touch it. The mechanism has to manufacture its own
//! ground truth -- **canaries**, artifacts the protocol knows are invalid, mixed
//! indistinguishably into the sample -- and then the punishment is unconditional
//! and the equilibrium moves. [`design::minimum_canary_rate`] solves for how
//! many are needed; `mechanism::tests` proves the claim about equilibria at any
//! slash rather than asserting it.
//!
//! # Where the money comes from
//!
//! Not from a new mint. [`docs/economics.md`](https://github.com/aburan28/proofwork/blob/main/docs/economics.md)
//! makes the case that issuance not gated on funded demand is the grinding
//! attack wearing a different hat, and a per-block subsidy for node operators is
//! exactly that -- unbounded supply against unbounded claimed effort. So node
//! rewards are a **protocol fee on settlement**: a fraction of every bounty that
//! actually settles, split three ways across the services above.
//!
//! That choice is not free and the harness reports its cost. Security spend is
//! proportional to settled value, which is right in the limit and *zero at
//! launch* -- the bootstrap problem stated exactly rather than assumed away. See
//! [`design::participation`].
//!
//! # What "evaluate" means
//!
//! [`game`] implements the ladder -- individual rationality, Nash, strict Nash,
//! dominance, k-resilience, invasion resistance, sybil-proofness -- over exact
//! rationals ([`exact`]), so every verdict is a decidable comparison rather than
//! a float artifact. [`mechanism`] expresses proofwork's node game in that
//! vocabulary, [`dynamics`] asks where a population *lands* rather than where it
//! could rest, and [`design`] inverts the question: given costs, what is the
//! smallest canary rate, bond, and committee that make honesty the equilibrium.
//!
//! # What this is not
//!
//! A model. Every number below is a parameter someone has to measure, and the
//! harness's output is a conditional: *if* verification costs this and fraud
//! pays that, *then* these are the equilibria. It cannot tell you the fraud
//! rate, it assumes operators maximise money over one epoch, and it says nothing
//! about reputation, law, or the many operators who would run a node because
//! they want the thing to exist. Those effects are real and all of them point
//! the same way -- towards more honesty than this predicts -- which is the right
//! direction for a security argument to be wrong in.

pub mod design;
pub mod dynamics;
pub mod exact;
pub mod game;
pub mod mechanism;
pub mod robustness;
pub mod sweep;

use std::fmt;

pub use exact::Rat;
pub use game::{
    Criterion, Dominance, Game, GameError, Invades, Invasion, Stability, Sybil, Symmetric,
};
pub use mechanism::{
    Attest, Availability, Custody, RewardRule, Serve, Share, SplitIdentities, Verification,
};

/// Upper bound on any money parameter, in the ledger's unit of account.
///
/// About `1.1e12` -- a trillion units, which is far more than any modelled epoch
/// needs and far less than `u64::MAX`. The gap is deliberate and the reasoning
/// behind it is worth stating plainly, because an earlier version of this
/// constant was set from the wrong argument.
///
/// A payoff is a sum of products of a money amount and two or three rates. The
/// rates multiply, so their *denominators* multiply: three parameters each with
/// a denominator up to [`MAX_RATE_DEN`] produce a denominator of
/// `MAX_RATE_DEN^3` before anything is divided by a node count. Adding a term
/// with a small denominator to a term with a large one scales the small one's
/// numerator by the ratio, and that -- not the size of the money -- is what
/// approaches `i128`'s `1.7e38`.
///
/// So the honest claim is narrow: **within these bounds, no payoff in this
/// module has been observed to saturate**, checked by sweeping the extremes in
/// `saturation_is_unreachable_across_the_validated_space`. It is a tested
/// property, not a proved one, which is why [`Rat::is_extreme`] exists and why
/// [`design::ServiceFinding::exact`] carries the answer into every report rather
/// than trusting the bound to hold forever.
pub const MAX_UNITS: u64 = 1 << 40;

/// Upper bound on the denominator of any rate parameter.
///
/// A rate of `1/100_003` is not a more precise measurement than `1/100_000`; it
/// is a prime denominator that survives every cancellation and multiplies into
/// the next one. One in a hundred thousand is a fine enough grid to express a
/// fraud rate or a canary rate, and coarse enough that three of them multiplied
/// together leave room in `i128`.
pub const MAX_RATE_DEN: i128 = 100_000;

/// A parameter set that cannot be validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamError {
    /// A count that must be positive was zero.
    Empty { field: &'static str },
    /// A money amount above [`MAX_UNITS`].
    TooLarge { field: &'static str, value: u64 },
    /// A rate outside `[0, 1]`, or with a denominator above [`MAX_RATE_DEN`].
    BadRate { field: &'static str, value: Rat },
    /// The three service splits sum above one -- the fee pool would pay out more
    /// than it took in.
    SplitsExceedPool { total: Rat },
    /// Canaries plus genuine fraud exceed the whole sample.
    RatesExceedSample { total: Rat },
    /// A committee threshold of zero, above the committee size, or a committee
    /// larger than the network.
    BadThreshold {
        committee: u32,
        threshold: u32,
        nodes: u32,
    },
}

impl fmt::Display for ParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamError::Empty { field } => write!(f, "{field} must be positive"),
            ParamError::TooLarge { field, value } => {
                write!(f, "{field} of {value} exceeds the {MAX_UNITS} modelling bound")
            }
            ParamError::BadRate { field, value } => write!(
                f,
                "{field} of {value} is not a rate in [0, 1] with denominator at most {MAX_RATE_DEN}"
            ),
            ParamError::SplitsExceedPool { total } => write!(
                f,
                "service splits sum to {total}, which pays out more than the fee pool holds"
            ),
            ParamError::RatesExceedSample { total } => write!(
                f,
                "canary rate plus fraud rate is {total}, which is more than the whole sample"
            ),
            ParamError::BadThreshold {
                committee,
                threshold,
                nodes,
            } => write!(
                f,
                "committee of {committee} with threshold {threshold} out of {nodes} nodes is not a t-of-n"
            ),
        }
    }
}

impl std::error::Error for ParamError {}

/// Every number the node game is a function of.
///
/// Money is in the ledger's unit of account, per **epoch** -- the period over
/// which a fee pool accrues and is paid out. Rates are exact rationals and none
/// of them is a probability the protocol gets to choose except
/// [`NodeParams::canary_rate`], which is the point: it is the one knob that
/// manufactures ground truth.
///
/// The fields are public because this is an analyst's input, not a protocol
/// record -- there is no canonical encoding of it, nothing hashes it, and a
/// caller sweeping a parameter should not have to go through twenty setters.
/// [`NodeParams::validate`] is the gate, and every entry point in this module
/// calls it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeParams {
    // -- the network -------------------------------------------------------
    /// Node operators. Interchangeable, which is what lets [`mechanism`] use the
    /// symmetric representation and stay tractable at realistic sizes.
    pub nodes: u32,
    /// Value settled per epoch: the sum of rewards on bounties that actually
    /// paid out. The demand side, and the *only* source of node revenue.
    pub settled_value: u64,
    /// Protocol fee taken from settlement and paid to operators.
    pub fee: Rat,
    /// Share of the fee pool paid for re-verification.
    pub verify_split: Rat,
    /// Share of the fee pool paid for availability.
    pub availability_split: Rat,
    /// Share of the fee pool paid for share custody.
    pub custody_split: Rat,

    // -- what a node spends ------------------------------------------------
    /// Cost of re-running one objective's pinned verifier. The `replay` verifier
    /// re-runs a whole computation, so this is the parameter that varies most
    /// across the verification ladder and the one that decides whether the
    /// dilemma bites at all.
    pub verify_cost: u64,
    /// Cost per epoch of storing and serving the log.
    pub storage_cost: u64,
    /// Fixed cost per epoch of running a node at all: hardware, bandwidth,
    /// somebody's attention.
    pub operating_cost: u64,
    /// Cost of publishing one Shamir share at epoch end.
    pub publish_cost: u64,
    /// Bond posted per node, slashable and returnable.
    pub stake: u64,
    /// Cost of capital per epoch on the bond. Stake is not free: it is money not
    /// doing something else, and a mechanism that assumes otherwise
    /// systematically over-estimates how much security it has bought.
    pub capital_rate: Rat,

    // -- verification ------------------------------------------------------
    /// Fraction of stake burned for attesting to an artifact that is invalid.
    pub slash_rate: Rat,
    /// Fraction of a node's sample that is a **canary**: an artifact the
    /// protocol knows to be invalid, mixed in indistinguishably. The one
    /// parameter that converts a conditional punishment into an unconditional
    /// one, and therefore the one that decides whether the honest profile is an
    /// equilibrium at all.
    pub canary_rate: Rat,
    /// Fraction of canaries that a node can *recognise* as canaries without
    /// running the verifier.
    ///
    /// A recognisable canary is worth nothing: a node that can spot one rejects
    /// it for free and rubber-stamps everything else, so the effective canary
    /// rate is `canary_rate * (1 - canary_leak)`. This is the assumption the
    /// whole mechanism rests on and it is an engineering problem, not an
    /// economic one -- canaries must be generated by the same pipeline as real
    /// submissions, by an author with the same identity distribution, against
    /// live objectives. It is set nonzero in the reference parameters
    /// deliberately, so no report ever quietly assumes perfection.
    pub canary_leak: Rat,
    /// Fraction of canaries that are *valid* artifacts rather than invalid ones.
    ///
    /// There are two ways to attest without looking, and a canary set of only
    /// known-bad artifacts punishes one of them. A node that blindly *rejects*
    /// everything passes every known-bad canary with flying colours; only a
    /// known-*good* canary catches it. So the mix matters, and the deterrent
    /// against each blind strategy is the canary rate times that strategy's
    /// share of the mix -- which means the binding constraint is whichever side
    /// is smaller, and an even split maximises the smaller side. See
    /// [`design::minimum_canary_rate`].
    pub canary_valid_share: Rat,
    /// Fraction of genuine submissions that are invalid. Not a design
    /// parameter -- a fact about submitters -- and the one that makes the naive
    /// bounty-only mechanism fail *worse* the more honest the network is.
    pub fraud_rate: Rat,
    /// Paid for catching an invalid artifact, split among the nodes that caught
    /// it.
    pub catch_bounty: u64,

    // -- availability ------------------------------------------------------
    /// Probability a node is challenged to produce a Merkle proof in an epoch.
    pub audit_rate: Rat,

    // -- custody -----------------------------------------------------------
    /// Members of the share-holding committee for sealed submissions.
    pub committee: u32,
    /// Shares needed to reconstruct. Raising it makes early opening harder and
    /// censorship by withholding easier; [`design::committee_window`] finds the
    /// values, if any, where neither pays.
    pub threshold: u32,
    /// Value of the largest sealed submission in an epoch -- what a cartel that
    /// opens early can front-run, or that a cartel that withholds can deny.
    pub sealed_value: u64,
    /// Probability that opening a sealed submission early is detected.
    pub detection_rate: Rat,

    // -- how the pools are divided -----------------------------------------
    /// How a service pool is split among the nodes that earned it.
    ///
    /// The one parameter here that is a pure design choice with a known right
    /// answer. An even per-node split pays for *identities*, so an operator
    /// maximises revenue by presenting one machine as forty; a stake-weighted
    /// split is exactly invariant to that, because stake is conserved when it is
    /// divided. It is a parameter rather than a constant so the report can show
    /// what the rejected alternative costs, in the units the alternative is
    /// usually argued for.
    pub reward_rule: RewardRule,
}

impl NodeParams {
    /// A reference network, and the numbers the docs and the CLI quote.
    ///
    /// Chosen so the interesting constraints are close to binding rather than
    /// comfortably satisfied: a parameter set where everything passes by two
    /// orders of magnitude demonstrates nothing about the mechanism, only about
    /// the person who picked the numbers.
    pub fn reference() -> NodeParams {
        NodeParams {
            nodes: 100,
            settled_value: 10_000_000,
            fee: rate(5, 100),
            verify_split: rate(1, 2),
            availability_split: rate(3, 10),
            custody_split: rate(1, 5),

            verify_cost: 200,
            storage_cost: 500,
            operating_cost: 2_000,
            publish_cost: 100,
            // Big enough that eleven committee members cannot profitably open a
            // two-million-unit envelope early: `t * d * slash` must clear the
            // value guarded, and at a tenth slashed that means millions bonded.
            // `design::minimum_stake_for_custody` is where this number comes
            // from, and it is the single largest cost the mechanism imposes.
            stake: 4_000_000,
            capital_rate: rate(1, 10_000),

            slash_rate: rate(1, 10),
            canary_rate: rate(1, 100),
            canary_leak: rate(1, 20),
            canary_valid_share: rate(1, 2),
            fraud_rate: rate(1, 1_000),
            catch_bounty: 50_000,

            audit_rate: rate(1, 10),

            committee: 21,
            threshold: 11,
            sealed_value: 2_000_000,
            detection_rate: rate(1, 2),

            reward_rule: RewardRule::PerStake,
        }
    }

    /// Refuse a parameter set that is not a network.
    ///
    /// Every entry point calls this. Validation is not defensive programming
    /// here -- it is what makes the arithmetic bound in [`exact`] hold, so
    /// skipping it does not merely risk a nonsense answer, it risks a saturated
    /// one that *looks* like an answer.
    pub fn validate(&self) -> Result<(), ParamError> {
        positive(self.nodes, "nodes")?;
        positive(self.committee, "committee")?;
        for (field, value) in self.money() {
            if value > MAX_UNITS {
                return Err(ParamError::TooLarge { field, value });
            }
        }
        for (field, value) in self.rates() {
            if value.is_negative() || value > Rat::ONE || value.denominator() > MAX_RATE_DEN {
                return Err(ParamError::BadRate { field, value });
            }
        }
        let splits = self.verify_split + self.availability_split + self.custody_split;
        if splits > Rat::ONE {
            return Err(ParamError::SplitsExceedPool { total: splits });
        }
        let sample = self.canary_rate + self.fraud_rate;
        if sample > Rat::ONE {
            return Err(ParamError::RatesExceedSample { total: sample });
        }
        if self.threshold == 0 || self.threshold > self.committee || self.committee > self.nodes {
            return Err(ParamError::BadThreshold {
                committee: self.committee,
                threshold: self.threshold,
                nodes: self.nodes,
            });
        }
        Ok(())
    }

    /// Fee revenue per epoch, before it is split across services.
    pub fn fee_pool(&self) -> Rat {
        Rat::units(self.settled_value) * self.fee
    }

    /// The verification pool for one epoch.
    pub fn verify_pool(&self) -> Rat {
        self.fee_pool() * self.verify_split
    }

    /// The availability pool for one epoch.
    pub fn availability_pool(&self) -> Rat {
        self.fee_pool() * self.availability_split
    }

    /// The custody pool for one epoch.
    pub fn custody_pool(&self) -> Rat {
        self.fee_pool() * self.custody_split
    }

    /// Stake actually destroyed by one slashing event.
    pub fn slash(&self) -> Rat {
        Rat::units(self.stake) * self.slash_rate
    }

    /// Canaries a rubber-stamping node cannot see coming.
    ///
    /// The rate the mechanism gets to rely on, as opposed to the rate it
    /// advertises. See [`NodeParams::canary_leak`].
    pub fn effective_canary_rate(&self) -> Rat {
        self.canary_rate * (Rat::ONE - self.canary_leak)
    }

    /// Cost of running a node for an epoch, before any service is performed.
    ///
    /// Sunk with respect to every sub-game: an operator that has already decided
    /// to run pays this whether it verifies or rubber-stamps, so it cancels out
    /// of the incentive comparisons and appears only in the participation
    /// constraint ([`design::participation`]). Separating the two is not a
    /// simplification -- conflating them is the error that lets a mechanism look
    /// incentive-compatible because it is expensive.
    pub fn fixed_cost(&self) -> Rat {
        Rat::units(self.operating_cost) + Rat::units(self.stake) * self.capital_rate
    }

    fn money(&self) -> [(&'static str, u64); 8] {
        [
            ("settled_value", self.settled_value),
            ("verify_cost", self.verify_cost),
            ("storage_cost", self.storage_cost),
            ("operating_cost", self.operating_cost),
            ("publish_cost", self.publish_cost),
            ("stake", self.stake),
            ("catch_bounty", self.catch_bounty),
            ("sealed_value", self.sealed_value),
        ]
    }

    fn rates(&self) -> [(&'static str, Rat); 11] {
        [
            ("fee", self.fee),
            ("verify_split", self.verify_split),
            ("availability_split", self.availability_split),
            ("custody_split", self.custody_split),
            ("capital_rate", self.capital_rate),
            ("slash_rate", self.slash_rate),
            ("canary_rate", self.canary_rate),
            ("canary_leak", self.canary_leak),
            ("canary_valid_share", self.canary_valid_share),
            ("fraud_rate", self.fraud_rate),
            ("audit_rate", self.audit_rate),
        ]
    }
}

impl Default for NodeParams {
    fn default() -> NodeParams {
        NodeParams::reference()
    }
}

fn positive(value: u32, field: &'static str) -> Result<(), ParamError> {
    if value == 0 {
        Err(ParamError::Empty { field })
    } else {
        Ok(())
    }
}

/// A rate literal for parameter sets, where the arguments are known good.
///
/// Panic-free: an out-of-range literal collapses to zero rather than aborting,
/// and [`NodeParams::validate`] is what a caller is meant to rely on. This is
/// only ever used with constants that are visibly in range.
fn rate(num: u32, den: u32) -> Rat {
    Rat::rate(num, den).unwrap_or(Rat::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incentive::game::Symmetric;

    #[test]
    fn the_reference_network_validates() {
        assert_eq!(NodeParams::reference().validate(), Ok(()));
        assert_eq!(NodeParams::default(), NodeParams::reference());
    }

    #[test]
    fn pools_split_the_fee_and_nothing_more() {
        let params = NodeParams::reference();
        assert_eq!(params.fee_pool(), Rat::units(500_000));
        assert_eq!(
            params.verify_pool() + params.availability_pool() + params.custody_pool(),
            params.fee_pool(),
            "the reference splits are exhaustive"
        );
        assert_eq!(params.verify_pool(), Rat::units(250_000));
    }

    #[test]
    fn a_leaky_canary_is_discounted_rather_than_believed() {
        let params = NodeParams::reference();
        // 1/100 advertised, 5% recognisable, so 19/2000 is what bites.
        assert_eq!(
            params.effective_canary_rate(),
            Rat::new(19, 2000).expect("valid rational")
        );
        let perfect = NodeParams {
            canary_leak: Rat::ZERO,
            ..NodeParams::reference()
        };
        assert_eq!(perfect.effective_canary_rate(), perfect.canary_rate);
        let useless = NodeParams {
            canary_leak: Rat::ONE,
            ..NodeParams::reference()
        };
        assert_eq!(
            useless.effective_canary_rate(),
            Rat::ZERO,
            "a canary everyone can spot is not a canary"
        );
    }

    #[test]
    fn validation_rejects_each_way_a_parameter_set_stops_being_a_network() {
        let base = NodeParams::reference();
        assert_eq!(
            NodeParams {
                nodes: 0,
                ..base.clone()
            }
            .validate(),
            Err(ParamError::Empty { field: "nodes" })
        );
        assert_eq!(
            NodeParams {
                stake: MAX_UNITS + 1,
                ..base.clone()
            }
            .validate(),
            Err(ParamError::TooLarge {
                field: "stake",
                value: MAX_UNITS + 1
            })
        );
        assert_eq!(
            NodeParams {
                verify_split: Rat::ONE,
                ..base.clone()
            }
            .validate(),
            Err(ParamError::SplitsExceedPool {
                total: Rat::new(3, 2).expect("valid rational")
            })
        );
        assert_eq!(
            NodeParams {
                fraud_rate: Rat::ONE,
                ..base.clone()
            }
            .validate(),
            Err(ParamError::RatesExceedSample {
                total: Rat::new(101, 100).expect("valid rational")
            })
        );
        assert_eq!(
            NodeParams {
                threshold: 22,
                ..base.clone()
            }
            .validate(),
            Err(ParamError::BadThreshold {
                committee: 21,
                threshold: 22,
                nodes: 100
            })
        );
        assert_eq!(
            NodeParams {
                committee: 200,
                ..base.clone()
            }
            .validate(),
            Err(ParamError::BadThreshold {
                committee: 200,
                threshold: 11,
                nodes: 100
            })
        );
        // A rate with a denominator past the bound is refused even though it is
        // a perfectly good probability: it is the arithmetic that objects.
        let fine_grained = Rat::rate(1, MAX_RATE_DEN as u32 + 1).expect("a valid rate");
        assert_eq!(
            NodeParams {
                fraud_rate: fine_grained,
                ..base
            }
            .validate(),
            Err(ParamError::BadRate {
                field: "fraud_rate",
                value: fine_grained
            })
        );
    }

    #[test]
    fn saturation_is_unreachable_across_the_validated_space() {
        // Swept at the extremes of the validated space, where it breaks first:
        // the largest money, the most awkward rate denominators, the widest
        // population. Prime denominators are chosen on purpose -- they survive
        // every cancellation, so they are the worst case for the arithmetic.
        let extreme = NodeParams {
            nodes: 100_000,
            settled_value: MAX_UNITS,
            fee: Rat::ONE,
            verify_split: Rat::ONE,
            availability_split: Rat::ZERO,
            custody_split: Rat::ZERO,
            verify_cost: MAX_UNITS,
            storage_cost: MAX_UNITS,
            operating_cost: MAX_UNITS,
            publish_cost: MAX_UNITS,
            stake: MAX_UNITS,
            capital_rate: Rat::ONE,
            slash_rate: Rat::ONE,
            canary_rate: Rat::rate(99_999, 100_000).expect("a valid rate"),
            canary_leak: Rat::rate(1, 99_991).expect("a valid rate"),
            canary_valid_share: Rat::rate(1, 99_991).expect("a valid rate"),
            fraud_rate: Rat::rate(1, 100_000).expect("a valid rate"),
            catch_bounty: MAX_UNITS,
            audit_rate: Rat::rate(99_991, 100_000).expect("a valid rate"),
            committee: 99,
            threshold: 50,
            sealed_value: MAX_UNITS,
            detection_rate: Rat::rate(1, 99_991).expect("a valid rate"),
            reward_rule: RewardRule::PerStake,
        };
        assert_eq!(extreme.validate(), Ok(()));

        let verification = Verification::new(&extreme).expect("validated");
        let custody = Custody::new(&extreme).expect("validated");
        let availability = Availability::new(&extreme).expect("validated");
        let mut checked = 0;
        for (verifiers, stampers) in [(0u32, 0u32), (1, 0), (0, 1), (50_000, 49_999)] {
            let others = vec![
                verifiers,
                stampers,
                extreme.nodes - 1 - verifiers - stampers,
            ];
            for action in 0..verification.actions() {
                let payoff = verification.payoff(action, &others);
                assert!(!payoff.is_extreme(), "verification payoff saturated");
                checked += 1;
            }
        }
        for cartel in [0u32, 1, 49, 50, 98] {
            let others = vec![extreme.committee - 1 - cartel, 0, cartel];
            for action in 0..custody.actions() {
                let payoff = custody.payoff(action, &others);
                assert!(!payoff.is_extreme(), "custody payoff saturated");
                checked += 1;
            }
        }
        for action in 0..availability.actions() {
            let payoff = availability.payoff(action, &[extreme.nodes - 1, 0]);
            assert!(!payoff.is_extreme(), "availability payoff saturated");
            checked += 1;
        }
        assert_eq!(
            checked,
            16 + 15 + 2,
            "every action at every probe was examined"
        );
    }
}
