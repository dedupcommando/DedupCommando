// SPDX-License-Identifier: Apache-2.0
pub mod action;
pub mod dataset;
pub mod duplicate;
/// The omission ledger's types. Inert in R3A — the schema and the store API exist, but nothing in
/// production records an omission or asks for a completeness verdict yet, so the module is
/// unreachable until R3B starts producing and R3D starts consuming.
#[allow(dead_code)]
pub mod omission;
/// The destructive-plan authority: both windows plan through it, and since R4B-2c every plan
/// is keyed by published `GroupId` identity and owns the witness the apply lease revalidates.
/// The narrow allow covers staged pieces awaiting their consumer (`RuntimeLedger` helpers a
/// later round wires), not the module as a whole any more.
#[allow(dead_code)]
pub mod plan;
pub mod preset;
pub mod reclaim;
pub mod scan;
