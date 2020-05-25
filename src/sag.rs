use crate::traits::{Sign, Verify};
use alloc::vec::Vec;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};

/// Spontaneous Anonymous Group (SAG) signatures
/// > This non-linkable ring signature that allows spontaneous groups, provided here for conceptual clarity
///
/// Please read tests at the bottom of the source code for this module for examples on how to use
/// it
pub struct SAG {
    challenge: Scalar,
    responses: Vec<Scalar>,
    ring: Vec<RistrettoPoint>,
}

impl Sign<Scalar, Vec<RistrettoPoint>> for SAG {
    /// To sign you need `k` your private key, and `ring` which is the public keys of everyone
    /// except you. You are signing the `message`
    fn sign<Hash: Digest<OutputSize = U64> + Clone, CSPRNG: CryptoRng + RngCore + Default>(
        k: Scalar,
        mut ring: Vec<RistrettoPoint>,
        message: &Vec<u8>,
    ) -> SAG {
        let mut csprng: CSPRNG = CSPRNG::default();
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;
        let n = ring.len() + 1;
        let secret_index = (csprng.next_u32() % n as u32) as usize;
        ring.insert(secret_index, k_point);
        let a: Scalar = Scalar::random(&mut csprng);
        let mut rs: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut csprng)).collect();
        let mut cs: Vec<Scalar> = (0..n).map(|_| Scalar::zero()).collect();
        let mut group_and_message_hash = Hash::new();
        for k_point in &ring {
            group_and_message_hash.input(k_point.compress().as_bytes());
        }
        group_and_message_hash.input(message);
        let mut hashes: Vec<Hash> = (0..n).map(|_| group_and_message_hash.clone()).collect();
        hashes[(secret_index + 1) % n].input(
            (a * constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        cs[(secret_index + 1) % n] = Scalar::from_hash(hashes[(secret_index + 1) % n].clone());
        let mut i = (secret_index + 1) % n;
        loop {
            hashes[(i + 1) % n].input(
                ((rs[i % n] * constants::RISTRETTO_BASEPOINT_POINT) + (cs[i % n] * ring[i % n]))
                    .compress()
                    .as_bytes(),
            );
            cs[(i + 1) % n] = Scalar::from_hash(hashes[(i + 1) % n].clone());
            if secret_index >= 1 && i % n == (secret_index - 1) % n {
                break;
            } else if secret_index == 0 && i % n == n - 1 {
                break;
            } else {
                i = (i + 1) % n;
            }
        }
        rs[secret_index] = a - (cs[secret_index] * k);
        return SAG {
            challenge: cs[0],
            responses: rs,
            ring: ring,
        };
    }
}

impl Verify for SAG {
    /// To verify a `signature` you need the `message` too
    fn verify<Hash: Digest<OutputSize = U64> + Clone>(signature: SAG, message: &Vec<u8>) -> bool {
        let n = signature.ring.len();
        let mut reconstructed_c: Scalar = signature.challenge;
        let mut group_and_message_hash = Hash::new();
        for k_point in &signature.ring {
            group_and_message_hash.input(k_point.compress().as_bytes());
        }
        group_and_message_hash.input(message);
        for j in 0..n {
            let mut h: Hash = group_and_message_hash.clone();
            h.input(
                ((signature.responses[j] * constants::RISTRETTO_BASEPOINT_POINT)
                    + (reconstructed_c * signature.ring[j]))
                    .compress()
                    .as_bytes(),
            );
            reconstructed_c = Scalar::from_hash(h);
        }

        return signature.challenge == reconstructed_c;
    }
}

#[cfg(test)]
mod test {
    extern crate blake2;
    extern crate rand;
    extern crate sha2;
    extern crate sha3;

    use super::*;
    use blake2::Blake2b;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;
    use sha2::Sha512;
    use sha3::Keccak512;

    #[test]
    fn sag() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let n = (csprng.next_u32() % 29 + 4) as usize;
        let ring: Vec<RistrettoPoint> = (0..(n - 1)) // Prover is going to add our key into this mix
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        let message: Vec<u8> = b"This is the message".iter().cloned().collect();

        {
            let signature = SAG::sign::<Sha512, OsRng>(k, ring.clone(), &message);
            let result = SAG::verify::<Sha512>(signature, &message);
            assert!(result);
        }

        {
            let signature = SAG::sign::<Keccak512, OsRng>(k, ring.clone(), &message);
            let result = SAG::verify::<Keccak512>(signature, &message);
            assert!(result);
        }

        {
            let signature = SAG::sign::<Blake2b, OsRng>(k, ring.clone(), &message);
            let result = SAG::verify::<Blake2b>(signature, &message);
            assert!(result);
        }
    }
}