use crate::prelude::*;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};

use crate::traits::{Sign, Verify};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Spontaneous Anonymous Group (SAG) signatures
/// > This non-linkable ring signature that allows spontaneous groups, provided here for conceptual clarity
///
/// Please read tests at the bottom of the source code for this module for examples on how to use
/// it
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone)]
pub struct SAG {
    pub challenge: Scalar,
    pub responses: Vec<Scalar>,
    pub ring: Vec<RistrettoPoint>,
}

impl Sign<Scalar, Vec<RistrettoPoint>> for SAG {
    /// To sign you need `k` your private key, and `ring` which is the public keys of everyone
    /// except you. You are signing the `message`
    fn sign<
        Hash: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Scalar,
        mut ring: Vec<RistrettoPoint>,
        secret_index: usize,
        message: &[u8],
    ) -> SAG {
        let mut csprng: CSPRNG = CSPRNG::default();
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;
        let n = ring.len() + 1;
        ring.insert(secret_index, k_point);
        let a: Scalar = Scalar::random(&mut csprng);
        let mut rs: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut csprng)).collect();
        let mut cs: Vec<Scalar> = (0..n).map(|_| Scalar::ZERO).collect();
        let mut group_and_message_hash = Hash::new();
        for k_point in &ring {
            group_and_message_hash.update(k_point.compress().as_bytes());
        }
        group_and_message_hash.update(message);
        let mut hashes: Vec<Hash> = (0..n).map(|_| group_and_message_hash.clone()).collect();
        hashes[(secret_index + 1) % n].update(
            (a * constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        cs[(secret_index + 1) % n] = Scalar::from_hash(hashes[(secret_index + 1) % n].clone());
        let mut i = (secret_index + 1) % n;
        loop {
            hashes[(i + 1) % n].update(
                RistrettoPoint::multiscalar_mul(
                    &[rs[i % n], cs[i % n]],
                    &[constants::RISTRETTO_BASEPOINT_POINT, ring[i % n]],
                )
                .compress()
                .as_bytes(),
            );
            cs[(i + 1) % n] = Scalar::from_hash(hashes[(i + 1) % n].clone());
            if (secret_index >= 1 && i % n == (secret_index - 1) % n)
                || (secret_index == 0 && i % n == n - 1)
            {
                break;
            } else {
                i = (i + 1) % n;
            }
        }
        rs[secret_index] = a - (cs[secret_index] * k);
        SAG {
            challenge: cs[0],
            responses: rs,
            ring,
        }
    }
}

impl Verify for SAG {
    /// To verify a `signature` you need the `message` too
    fn verify<Hash: Digest<OutputSize = U64> + Clone + Default>(
        signature: SAG,
        message: &[u8],
    ) -> bool {
        let n = signature.ring.len();
        let mut reconstructed_c: Scalar = signature.challenge;
        let mut group_and_message_hash = Hash::new();
        for k_point in &signature.ring {
            group_and_message_hash.update(k_point.compress().as_bytes());
        }
        group_and_message_hash.update(message);
        for j in 0..n {
            let mut h: Hash = group_and_message_hash.clone();
            h.update(
                RistrettoPoint::multiscalar_mul(
                    &[signature.responses[j], reconstructed_c],
                    &[constants::RISTRETTO_BASEPOINT_POINT, signature.ring[j]],
                )
                .compress()
                .as_bytes(),
            );
            reconstructed_c = Scalar::from_hash(h);
        }

        signature.challenge == reconstructed_c
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "std")]
    mod std_tests {
        use super::super::*;
        use blake2::Blake2b512;
        use curve25519_dalek::ristretto::RistrettoPoint;
        use curve25519_dalek::scalar::Scalar;
        use rand::rngs::OsRng;
        use sha2::Sha512;
        use sha3::Keccak512;

        #[test]
        fn sag() {
            let mut csprng = OsRng::default();
            let k: Scalar = Scalar::random(&mut csprng);
            let secret_index = 1;
            let n = 2;
            let ring: Vec<RistrettoPoint> =
                (0..(n - 1)) // Prover is going to add our key into this mix
                    .map(|_| RistrettoPoint::random(&mut csprng))
                    .collect();
            let message: Vec<u8> = b"This is the message".iter().cloned().collect();

            {
                let signature = SAG::sign::<Sha512, OsRng>(k, ring.clone(), secret_index, &message);
                let result = SAG::verify::<Sha512>(signature, &message);
                assert!(result);
            }

            {
                let signature =
                    SAG::sign::<Keccak512, OsRng>(k, ring.clone(), secret_index, &message);
                let result = SAG::verify::<Keccak512>(signature, &message);
                assert!(result);
            }

            {
                let signature =
                    SAG::sign::<Blake2b512, OsRng>(k, ring.clone(), secret_index, &message);
                let result = SAG::verify::<Blake2b512>(signature, &message);
                assert!(result);
            }
        }
    }
}
