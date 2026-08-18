//! Restart-convergent orchestration for explicit installation-data purge.
//!
//! This module deliberately owns no paths, filesystem calls, process handles,
//! or Windows APIs. The production adapter supplies those effects while the
//! state machine fixes their order and makes every completed effect replayable.

#![allow(clippy::missing_errors_doc)]

use std::fmt;

const MAX_CONVERGENCE_STEPS: usize = 16;

/// Durable installation lifecycle observed by the purge controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PurgeRecordState {
    Absent,
    Installing,
    Active,
    Removing,
    Retained,
    Purging,
    Broken,
}

/// Presence of the record-derived source and deterministic tombstone trees.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PurgeTreeState {
    Source,
    Tombstone,
    Gone,
    Both,
}

/// One detached observation made without retaining a filesystem reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PurgeObservation {
    pub record: PurgeRecordState,
    pub tree: PurgeTreeState,
}

/// Successful explicit-purge outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PurgeOutcome {
    Purged,
    AlreadyAbsent,
}

/// Stable orchestration error. Native details remain inside the adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PurgeConvergenceError<E> {
    Effect(E),
    Drift,
    DidNotConverge,
}

impl<E: fmt::Display> fmt::Display for PurgeConvergenceError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Effect(error) => write!(formatter, "purge effect failed: {error}"),
            Self::Drift => formatter.write_str("purge evidence drifted"),
            Self::DidNotConverge => formatter.write_str("purge did not converge"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for PurgeConvergenceError<E> {}

/// High-level effects required by the pure purge convergence loop.
///
/// Implementations must internally enforce the lock and evidence contracts
/// documented on each method. In particular, they never accept a caller path,
/// install identity, task name, or tombstone name.
pub trait PurgeEnvironment {
    type Error;

    /// Observes the exact durable record and its record-derived tree pair.
    fn observe(&mut self) -> Result<PurgeObservation, Self::Error>;

    /// Proves an absent record has no identity-bearing source or tombstone.
    fn verify_clean_absence(&mut self) -> Result<(), Self::Error>;

    /// Validates the external controller plus every complete retained artifact.
    ///
    /// This runs before the first lifecycle/task mutation. It must prove exact
    /// record paths, runtime trust, key/data identity, and Task ownership.
    /// `state` freezes the task rule: ACTIVE requires the exact owned task,
    /// REMOVING accepts that exact task or prior exact absence, and RETAINED
    /// requires absence. Implementations must not collapse those checkpoints
    /// into one "task must exist" predicate.
    fn preflight_complete_record(&mut self, state: PurgeRecordState) -> Result<(), Self::Error>;

    /// Converges ACTIVE/REMOVING to RETAINED under the installation fence.
    fn converge_retained(&mut self) -> Result<(), Self::Error>;

    /// Publishes RETAINED -> PURGING, drains in-tree actors, and stages Source.
    ///
    /// This is one adapter operation because the daemon-lock proof acquired
    /// before the CAS must remain continuously held through the startup-lock
    /// handoff. It may fail after any durable sub-effect; a later observation
    /// then resumes from RETAINED, PURGING+Source, or PURGING+Tombstone.
    fn publish_purging_and_stage_source(&mut self) -> Result<(), Self::Error>;

    /// Revalidates only the external controller and durable PURGING record.
    /// Deleted runtime/data bytes are intentionally not required on resume.
    fn preflight_purging_resume(&mut self, tree: PurgeTreeState) -> Result<(), Self::Error>;

    /// Re-establishes the daemon/startup fence after a crash in PURGING+Source,
    /// drains it without lock inversion, and stages the deterministic source.
    fn resume_purging_source(&mut self) -> Result<(), Self::Error>;

    /// Performs a complete non-following audit, then deletes the tombstone.
    fn audit_and_delete_tombstone(&mut self) -> Result<(), Self::Error>;

    /// Deletes validated stage siblings and the exact PURGING record last.
    fn finalize_record_last(&mut self) -> Result<(), Self::Error>;
}

/// Converges an explicit purge to record/tree absence.
///
/// The bounded loop is not a retry policy for arbitrary I/O. Each iteration
/// follows only a newly observed durable state after one successful idempotent
/// effect. Any adapter error returns immediately and is resumed by a later
/// invocation.
///
/// # Errors
///
/// Returns [`PurgeConvergenceError::Drift`] for an impossible/unsafe state,
/// [`PurgeConvergenceError::Effect`] for a typed adapter failure, or
/// [`PurgeConvergenceError::DidNotConverge`] if successful effects do not
/// advance the durable observation within the fixed bound.
pub fn converge_purge<E: PurgeEnvironment>(
    environment: &mut E,
) -> Result<PurgeOutcome, PurgeConvergenceError<E::Error>> {
    let mut changed = false;
    for _ in 0..MAX_CONVERGENCE_STEPS {
        let observed = environment
            .observe()
            .map_err(PurgeConvergenceError::Effect)?;
        match (observed.record, observed.tree) {
            (PurgeRecordState::Absent, PurgeTreeState::Gone) => {
                environment
                    .verify_clean_absence()
                    .map_err(PurgeConvergenceError::Effect)?;
                return Ok(if changed {
                    PurgeOutcome::Purged
                } else {
                    PurgeOutcome::AlreadyAbsent
                });
            }
            (
                PurgeRecordState::Absent | PurgeRecordState::Installing | PurgeRecordState::Broken,
                _,
            )
            | (_, PurgeTreeState::Both) => return Err(PurgeConvergenceError::Drift),
            (
                PurgeRecordState::Active | PurgeRecordState::Removing | PurgeRecordState::Retained,
                tree,
            ) => {
                if tree != PurgeTreeState::Source {
                    return Err(PurgeConvergenceError::Drift);
                }
                environment
                    .preflight_complete_record(observed.record)
                    .map_err(PurgeConvergenceError::Effect)?;
                if observed.record == PurgeRecordState::Retained {
                    environment
                        .publish_purging_and_stage_source()
                        .map_err(PurgeConvergenceError::Effect)?;
                } else {
                    environment
                        .converge_retained()
                        .map_err(PurgeConvergenceError::Effect)?;
                }
                changed = true;
            }
            (PurgeRecordState::Purging, tree) => {
                environment
                    .preflight_purging_resume(tree)
                    .map_err(PurgeConvergenceError::Effect)?;
                match tree {
                    PurgeTreeState::Source => environment
                        .resume_purging_source()
                        .map_err(PurgeConvergenceError::Effect)?,
                    PurgeTreeState::Tombstone => environment
                        .audit_and_delete_tombstone()
                        .map_err(PurgeConvergenceError::Effect)?,
                    PurgeTreeState::Gone => environment
                        .finalize_record_last()
                        .map_err(PurgeConvergenceError::Effect)?,
                    PurgeTreeState::Both => unreachable!("handled above"),
                }
                changed = true;
            }
        }
    }
    Err(PurgeConvergenceError::DidNotConverge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        Injected,
    }

    impl fmt::Display for Fault {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected")
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Effect {
        Retain,
        Publish,
        Drain,
        Stage,
        DeleteTree,
        DeleteRecord,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FaultTiming {
        Before,
        After,
    }

    struct Fake {
        observation: PurgeObservation,
        effects: Vec<Effect>,
        fault: Option<(Effect, FaultTiming)>,
    }

    impl Fake {
        fn active() -> Self {
            Self {
                observation: PurgeObservation {
                    record: PurgeRecordState::Active,
                    tree: PurgeTreeState::Source,
                },
                effects: Vec::new(),
                fault: None,
            }
        }

        fn effect(&mut self, effect: Effect) -> Result<(), Fault> {
            if self.fault == Some((effect, FaultTiming::Before)) {
                self.fault = None;
                return Err(Fault::Injected);
            }
            self.effects.push(effect);
            match effect {
                Effect::Retain => self.observation.record = PurgeRecordState::Retained,
                Effect::Publish => self.observation.record = PurgeRecordState::Purging,
                Effect::Drain => {}
                Effect::Stage => self.observation.tree = PurgeTreeState::Tombstone,
                Effect::DeleteTree => self.observation.tree = PurgeTreeState::Gone,
                Effect::DeleteRecord => self.observation.record = PurgeRecordState::Absent,
            }
            if self.fault == Some((effect, FaultTiming::After)) {
                self.fault = None;
                return Err(Fault::Injected);
            }
            Ok(())
        }
    }

    impl PurgeEnvironment for Fake {
        type Error = Fault;

        fn observe(&mut self) -> Result<PurgeObservation, Self::Error> {
            Ok(self.observation)
        }

        fn verify_clean_absence(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn preflight_complete_record(
            &mut self,
            _state: PurgeRecordState,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn converge_retained(&mut self) -> Result<(), Self::Error> {
            self.effect(Effect::Retain)
        }

        fn publish_purging_and_stage_source(&mut self) -> Result<(), Self::Error> {
            self.effect(Effect::Publish)?;
            self.effect(Effect::Drain)?;
            self.effect(Effect::Stage)
        }

        fn preflight_purging_resume(&mut self, _tree: PurgeTreeState) -> Result<(), Self::Error> {
            Ok(())
        }

        fn resume_purging_source(&mut self) -> Result<(), Self::Error> {
            self.effect(Effect::Drain)?;
            self.effect(Effect::Stage)
        }

        fn audit_and_delete_tombstone(&mut self) -> Result<(), Self::Error> {
            self.effect(Effect::DeleteTree)
        }

        fn finalize_record_last(&mut self) -> Result<(), Self::Error> {
            self.effect(Effect::DeleteRecord)
        }
    }

    #[test]
    fn active_purge_follows_the_frozen_record_last_order() {
        let mut fake = Fake::active();
        assert_eq!(converge_purge(&mut fake), Ok(PurgeOutcome::Purged));
        assert_eq!(
            fake.effects,
            [
                Effect::Retain,
                Effect::Publish,
                Effect::Drain,
                Effect::Stage,
                Effect::DeleteTree,
                Effect::DeleteRecord,
            ]
        );
    }

    #[test]
    fn every_completed_effect_can_fail_ambiguously_and_resume() {
        for timing in [FaultTiming::Before, FaultTiming::After] {
            for effect in [
                Effect::Retain,
                Effect::Publish,
                Effect::Drain,
                Effect::Stage,
                Effect::DeleteTree,
                Effect::DeleteRecord,
            ] {
                let mut fake = Fake::active();
                fake.fault = Some((effect, timing));
                assert_eq!(
                    converge_purge(&mut fake),
                    Err(PurgeConvergenceError::Effect(Fault::Injected))
                );
                let expected = if effect == Effect::DeleteRecord && timing == FaultTiming::After {
                    PurgeOutcome::AlreadyAbsent
                } else {
                    PurgeOutcome::Purged
                };
                assert_eq!(converge_purge(&mut fake), Ok(expected));
            }
        }
    }

    #[test]
    fn post_rename_recovery_never_reopens_in_tree_locks() {
        for tree in [PurgeTreeState::Tombstone, PurgeTreeState::Gone] {
            let mut fake = Fake {
                observation: PurgeObservation {
                    record: PurgeRecordState::Purging,
                    tree,
                },
                effects: Vec::new(),
                fault: Some((Effect::Drain, FaultTiming::Before)),
            };
            assert_eq!(converge_purge(&mut fake), Ok(PurgeOutcome::Purged));
            assert!(!fake.effects.contains(&Effect::Drain));
        }
    }

    #[test]
    fn absence_is_idempotent_and_impossible_tree_states_are_drift() {
        let mut absent = Fake {
            observation: PurgeObservation {
                record: PurgeRecordState::Absent,
                tree: PurgeTreeState::Gone,
            },
            effects: Vec::new(),
            fault: None,
        };
        assert_eq!(converge_purge(&mut absent), Ok(PurgeOutcome::AlreadyAbsent));

        for observation in [
            PurgeObservation {
                record: PurgeRecordState::Absent,
                tree: PurgeTreeState::Source,
            },
            PurgeObservation {
                record: PurgeRecordState::Retained,
                tree: PurgeTreeState::Tombstone,
            },
            PurgeObservation {
                record: PurgeRecordState::Purging,
                tree: PurgeTreeState::Both,
            },
            PurgeObservation {
                record: PurgeRecordState::Installing,
                tree: PurgeTreeState::Source,
            },
        ] {
            let mut fake = Fake {
                observation,
                effects: Vec::new(),
                fault: None,
            };
            assert_eq!(converge_purge(&mut fake), Err(PurgeConvergenceError::Drift));
            assert!(fake.effects.is_empty());
        }
    }

    #[test]
    fn successful_effect_without_durable_progress_hits_the_fixed_bound() {
        struct Stalled;

        impl PurgeEnvironment for Stalled {
            type Error = Fault;

            fn observe(&mut self) -> Result<PurgeObservation, Self::Error> {
                Ok(PurgeObservation {
                    record: PurgeRecordState::Active,
                    tree: PurgeTreeState::Source,
                })
            }

            fn verify_clean_absence(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }

            fn preflight_complete_record(
                &mut self,
                _state: PurgeRecordState,
            ) -> Result<(), Self::Error> {
                Ok(())
            }

            fn converge_retained(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }

            fn publish_purging_and_stage_source(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }

            fn preflight_purging_resume(
                &mut self,
                _tree: PurgeTreeState,
            ) -> Result<(), Self::Error> {
                Ok(())
            }

            fn resume_purging_source(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }

            fn audit_and_delete_tombstone(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }

            fn finalize_record_last(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        assert_eq!(
            converge_purge(&mut Stalled),
            Err(PurgeConvergenceError::DidNotConverge)
        );
    }
}
