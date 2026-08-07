//! Module for the `Ring` structure, ensuring sorted public keys for efficient signing.

use crate::prelude::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use digest::{generic_array::typenum::U64, Digest};

/// Represents pre-computed data for a `Ring` to accelerate cryptographic operations.
///
/// This structure holds the results of hashing each public key in the ring onto the curve.
/// By performing this computationally expensive step once and caching the result, both
/// signing and verification can be significantly sped up.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrecomputedRingData {
    hashed_points: Vec<RistrettoPoint>,
}

impl PrecomputedRingData {
    /// Returns a slice of the pre-computed hashed points.
    pub fn hashed_points(&self) -> &[RistrettoPoint] {
        &self.hashed_points
    }

    /// Verifies that the pre-computed data is valid for the given `Ring`.
    ///
    /// This is a crucial security step. It re-calculates the expected hashed points
    /// from the ring's public keys and compares them against the points stored in this
    /// pre-computed object to ensure they match. A user should always run this check
    /// on any pre-computed data received from an untrusted source.
    pub fn verify<H: Digest<OutputSize = U64> + Clone + Default>(&self, ring: &Ring) -> bool {
        if self.hashed_points.len() != ring.members.len() {
            return false;
        }
        let expected_points: Vec<RistrettoPoint> = ring
            .members
            .iter()
            .map(|p| RistrettoPoint::from_hash(H::default().chain_update(p.compress().to_bytes())))
            .collect();

        self.hashed_points == expected_points
    }
}

/// Represents a ring of public keys for a ring signature.
///
/// The `Ring` struct guarantees that its internal list of public keys is always
/// sorted by their byte representation. This is a critical invariant that allows
/// for high-performance binary searching during the signing process, avoiding
/// a slow linear scan.
#[derive(Clone, Debug)]
pub struct Ring {
    members: Vec<RistrettoPoint>,
}

impl Ring {
    /// Creates a new `Ring` from a vector of public keys.
    ///
    /// The constructor takes ownership of the vector and immediately sorts the
    /// public keys to enforce the struct's invariant.
    pub fn new(public_keys: Vec<RistrettoPoint>) -> Self {
        let mut members = public_keys;
        // Sort by the compressed byte representation to ensure a canonical ordering.
        members.sort_unstable_by_key(|p| p.compress().to_bytes());
        Self { members }
    }

    /// Returns a slice containing all the public key members of the ring, guaranteed
    /// to be in sorted order.
    pub fn members(&self) -> &[RistrettoPoint] {
        &self.members
    }

    /// Performs the pre-computation step for this ring.
    ///
    /// This iterates through all public keys in the ring, hashes them to a point on
    /// the curve, and returns a `PrecomputedRingData` object containing the results.
    /// This object can then be used to accelerate future signing and verification operations.
    pub fn precompute<H: Digest<OutputSize = U64> + Clone + Default>(&self) -> PrecomputedRingData {
        let hashed_points = self
            .members
            .iter()
            .map(|p| RistrettoPoint::from_hash(H::default().chain_update(p.compress().to_bytes())))
            .collect();
        PrecomputedRingData { hashed_points }
    }
}
