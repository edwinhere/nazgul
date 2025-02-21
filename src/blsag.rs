use crate::prelude::*;
use crate::traits::{KeyImageGen, Link, Sign, Verify};
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Back's Linkable Spontaneous Anonymous Group (bLSAG) signatures
/// > This an enhanced version of the LSAG algorithm where linkability
/// is independent of the ring's decoy members.
///
/// Please read tests at the bottom of the source code for this module for examples on how to use
/// it
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone)]
pub struct BLSAG {
    pub challenge: Scalar,
    pub responses: Vec<Scalar>,
    pub ring: Vec<RistrettoPoint>,
    pub key_image: RistrettoPoint,
}

impl KeyImageGen<Scalar, RistrettoPoint> for BLSAG {
    /// Some signature schemes require the key images to be signed as well.
    /// Use this method to generate them
    fn generate_key_image<Hash: Digest<OutputSize = U64> + Clone + Default>(
        k: Scalar,
    ) -> RistrettoPoint {
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let key_image: RistrettoPoint = k * RistrettoPoint::from_hash(
            Hash::default().chain_update(k_point.compress().as_bytes()),
        );

        return key_image;
    }
}

impl Sign<Scalar, Vec<RistrettoPoint>> for BLSAG {
    /// To sign you need `k` your private key, and `ring` which is the public keys of everyone
    /// except you. You are signing the `message`
    fn sign<
        Hash: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Scalar,
        mut ring: Vec<RistrettoPoint>,
        secret_index: usize,
        message: &Vec<u8>,
    ) -> BLSAG {
        let mut csprng = CSPRNG::default();

        // Provers public key
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let key_image: RistrettoPoint = BLSAG::generate_key_image::<Hash>(k);

        let n = ring.len() + 1;

        ring.insert(secret_index, k_point);

        let a: Scalar = Scalar::random(&mut csprng);

        let mut rs: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut csprng)).collect();

        let mut cs: Vec<Scalar> = (0..n).map(|_| Scalar::ZERO).collect();

        // Hash of message is shared by all challenges H_n(m, ....)
        let mut message_hash = Hash::default();

        message_hash.update(message);

        let mut hashes: Vec<Hash> = (0..n).map(|_| message_hash.clone()).collect();

        hashes[(secret_index + 1) % n].update(
            (a * constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        hashes[(secret_index + 1) % n].update(
            (a * RistrettoPoint::from_hash(
                Hash::default().chain_update(k_point.compress().as_bytes()),
            ))
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
            hashes[(i + 1) % n].update(
                RistrettoPoint::multiscalar_mul(
                    &[rs[i % n], cs[i % n]],
                    &[
                        RistrettoPoint::from_hash(
                            Hash::default().chain_update(ring[i % n].compress().as_bytes()),
                        ),
                        key_image,
                    ],
                )
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

        return BLSAG {
            challenge: cs[0],
            responses: rs,
            ring: ring,
            key_image: key_image,
        };
    }
}

impl Verify for BLSAG {
    /// To verify a `signature` you need the `message` too
    fn verify<Hash: Digest<OutputSize = U64> + Clone + Default>(
        signature: BLSAG,
        message: &Vec<u8>,
    ) -> bool {
        let mut reconstructed_c: Scalar = signature.challenge;
        let n = signature.ring.len();
        for j in 0..n {
            let mut h: Hash = Hash::default();
            h.update(message);
            h.update(
                RistrettoPoint::multiscalar_mul(
                    &[signature.responses[j], reconstructed_c],
                    &[constants::RISTRETTO_BASEPOINT_POINT, signature.ring[j]],
                )
                .compress()
                .as_bytes(),
            );

            h.update(
                RistrettoPoint::multiscalar_mul(
                    &[signature.responses[j], reconstructed_c],
                    &[
                        RistrettoPoint::from_hash(
                            Hash::default().chain_update(signature.ring[j].compress().as_bytes()),
                        ),
                        signature.key_image,
                    ],
                )
                .compress()
                .as_bytes(),
            );
            reconstructed_c = Scalar::from_hash(h);
        }

        return signature.challenge == reconstructed_c;
    }
}

impl Link for BLSAG {
    /// This is for linking two signatures and checking if they are signed by the same person
    fn link(signature_1: BLSAG, signature_2: BLSAG) -> bool {
        return signature_1.key_image == signature_2.key_image;
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    extern crate blake2;
    extern crate rand;
    extern crate sha2;
    extern crate sha3;

    use super::*;
    use blake2::Blake2b512;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;
    use sha2::Sha512;
    use sha3::Keccak512;

    #[test]
    fn blsag() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let secret_index = 1;
        let n = 2;
        let ring: Vec<RistrettoPoint> = (0..(n - 1)) // Prover is going to add our key into this mix
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        let message: Vec<u8> = b"This is the message".iter().cloned().collect();

        {
            let signature = BLSAG::sign::<Sha512, OsRng>(k, ring.clone(), secret_index, &message);
            let result = BLSAG::verify::<Sha512>(signature, &message);
            assert!(result);
        }

        {
            let signature =
                BLSAG::sign::<Keccak512, OsRng>(k, ring.clone(), secret_index, &message);
            let result = BLSAG::verify::<Keccak512>(signature, &message);
            assert!(result);
        }

        {
            let signature =
                BLSAG::sign::<Blake2b512, OsRng>(k, ring.clone(), secret_index, &message);
            let result = BLSAG::verify::<Blake2b512>(signature, &message);
            assert!(result);
        }

        let another_ring: Vec<RistrettoPoint> =
            (0..(n - 1)) // Prover is going to add our key into this mix
                .map(|_| RistrettoPoint::random(&mut csprng))
                .collect();
        let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
        let signature_1 = BLSAG::sign::<Blake2b512, OsRng>(
            k,
            another_ring.clone(),
            secret_index,
            &another_message,
        );
        let signature_2 = BLSAG::sign::<Blake2b512, OsRng>(k, ring.clone(), secret_index, &message);
        let result = BLSAG::link(signature_1, signature_2);
        assert!(result);
    }
}
