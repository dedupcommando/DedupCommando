// SPDX-License-Identifier: Apache-2.0
pub mod action;
pub mod dataset;
pub mod duplicate;
/// The omission ledger's types. Inert in R3A — the schema and the store API exist, but nothing in
/// production records an omission or asks for a completeness verdict yet, so the module is
/// unreachable until R3B starts producing and R3D starts consuming.
#[allow(dead_code)]
pub mod omission;
/// The destructive-plan authority. Inert in R2D-C5-1 — nothing in production builds a plan from it
/// yet, so the whole module is unreachable until R2D-C5-2 switches the consumers onto it.
#[allow(dead_code)]
pub mod plan;
pub mod preset;
pub mod reclaim;
pub mod scan;
