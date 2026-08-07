//! Back's Linkable Spontaneous Anonymous Group (bLSAG) signatures

use crate::prelude::*;
use crate::ring::{PrecomputedRingData, Ring};
use crate::traits::{KeyImageGen, LinkRef, SignRef, VerifyRef};
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Back's Linkable Spontaneous Anonymous Group (bLSAG) signatures
/// > This an enhanced version of the LSAG algorithm where linkability
/// > is independent of the ring's decoy members.
///
/// Please read tests at the bottom of the source code for this module for examples on how to use
/// it
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone)]
pub struct BLSAG {
    challenge: Scalar,
    responses: Vec<Scalar>,
    key_image: RistrettoPoint,
}

impl BLSAG {
    pub fn key_image(&self) -> RistrettoPoint {
        self.key_image
    }
}

/// Private helper function to perform the core cryptographic hashing used in both
/// signing and verification. This prevents code duplication.
fn hash_ring_member_components<H: Digest<OutputSize = U64> + Clone + Default>(
    message_hash: &H,
    response: Scalar,
    challenge: Scalar,
    public_key: RistrettoPoint,
    key_image: RistrettoPoint,
    precomputed_pk_hash: Option<RistrettoPoint>,
) -> Scalar {
    let mut h = message_hash.clone();
    h.update(
        RistrettoPoint::vartime_multiscalar_mul(
            &[response, challenge],
            &[constants::RISTRETTO_BASEPOINT_POINT, public_key],
        )
        .compress()
        .as_bytes(),
    );

    let pk_hash = precomputed_pk_hash.unwrap_or_else(|| {
        RistrettoPoint::from_hash(H::default().chain_update(public_key.compress().as_bytes()))
    });

    h.update(
        RistrettoPoint::vartime_multiscalar_mul(&[response, challenge], &[pk_hash, key_image])
            .compress()
            .as_bytes(),
    );
    Scalar::from_hash(h)
}

impl KeyImageGen<Scalar, RistrettoPoint> for BLSAG {
    /// Some signature schemes require the key images to be signed as well.
    /// Use this method to generate them
    fn generate_key_image<H: Digest<OutputSize = U64> + Clone + Default>(
        k: Scalar,
    ) -> RistrettoPoint {
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let key_image: RistrettoPoint =
            k * RistrettoPoint::from_hash(H::default().chain_update(k_point.compress().as_bytes()));

        key_image
    }
}

impl SignRef<Scalar> for BLSAG {
    /// To sign you need `k` your private key, and `ring` which is the public keys of everyone
    /// except you. You are signing the `message`
    fn sign<
        H: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PrecomputedRingData>,
        message: &[u8],
    ) -> Result<BLSAG, SignatureError> {
        let mut csprng = CSPRNG::default();
        let ring_members = ring.members();

        // Provers public key
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let secret_index = ring_members
            .binary_search_by_key(&k_point.compress().to_bytes(), |p| p.compress().to_bytes())
            .map_err(|_| SignatureError::SignerNotFound)?;

        let key_image: RistrettoPoint = BLSAG::generate_key_image::<H>(k);

        let n = ring_members.len();

        let a: Scalar = Scalar::random(&mut csprng);

        let mut rs: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut csprng)).collect();

        let mut cs: Vec<Scalar> = (0..n).map(|_| Scalar::ZERO).collect();

        // Hash of message is shared by all challenges H_n(m, ....)
        let mut message_hash = H::default();
        message_hash.update(message);

        let mut h = message_hash.clone();
        h.update(
            (a * constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        h.update(
            (a * RistrettoPoint::from_hash(
                H::default().chain_update(k_point.compress().as_bytes()),
            ))
            .compress()
            .as_bytes(),
        );
        cs[(secret_index + 1) % n] = Scalar::from_hash(h);

        let mut i = (secret_index + 1) % n;

        loop {
            cs[(i + 1) % n] = hash_ring_member_components(
                &message_hash,
                rs[i % n],
                cs[i % n],
                ring_members[i % n],
                key_image,
                precomputed_data.map(|d| d.hashed_points()[i % n]),
            );

            if (secret_index >= 1 && i % n == (secret_index - 1) % n)
                || (secret_index == 0 && i % n == n - 1)
            {
                break;
            } else {
                i = (i + 1) % n;
            }
        }

        rs[secret_index] = a - (cs[secret_index] * k);

        Ok(BLSAG {
            challenge: cs[0],
            responses: rs,
            key_image,
        })
    }
}

impl VerifyRef for BLSAG {
    /// To verify a `signature` you need the `message` too
    fn verify<H: Digest<OutputSize = U64> + Clone + Default>(
        signature: &BLSAG,
        ring: &Ring,
        precomputed_data: Option<&PrecomputedRingData>,
        message: &[u8],
    ) -> bool {
        let mut reconstructed_c: Scalar = signature.challenge;
        let message_hash = H::default().chain_update(message);
        let ring_members = ring.members();

        for (j, ring_member) in ring_members.iter().enumerate() {
            reconstructed_c = hash_ring_member_components(
                &message_hash,
                signature.responses[j],
                reconstructed_c,
                *ring_member,
                signature.key_image,
                precomputed_data.map(|d| d.hashed_points()[j]),
            );
        }

        signature.challenge == reconstructed_c
    }
}

impl LinkRef for BLSAG {
    /// This is for linking two signatures and checking if they are signed by the same person
    fn link(signature_1: &BLSAG, signature_2: &BLSAG) -> bool {
        signature_1.key_image() == signature_2.key_image()
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
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;
        let n = 2;
        let mut public_keys: Vec<RistrettoPoint> = (0..(n - 1))
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys.push(k_point);
        let ring = Ring::new(public_keys);
        let message: Vec<u8> = b"This is the message".iter().cloned().collect();

        {
            let signature = BLSAG::sign::<Sha512, OsRng>(k, &ring, None, &message).unwrap();
            let result = BLSAG::verify::<Sha512>(&signature, &ring, None, &message);
            assert!(result);
        }

        {
            let signature = BLSAG::sign::<Keccak512, OsRng>(k, &ring, None, &message).unwrap();
            let result = BLSAG::verify::<Keccak512>(&signature, &ring, None, &message);
            assert!(result);
        }

        {
            let signature = BLSAG::sign::<Blake2b512, OsRng>(k, &ring, None, &message).unwrap();
            let result = BLSAG::verify::<Blake2b512>(&signature, &ring, None, &message);
            assert!(result);
        }

        let mut another_public_keys: Vec<RistrettoPoint> = (0..(n - 1))
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        another_public_keys.push(k_point);
        let another_ring = Ring::new(another_public_keys);
        let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
        let signature_1 =
            BLSAG::sign::<Blake2b512, OsRng>(k, &another_ring, None, &another_message).unwrap();
        let signature_2 = BLSAG::sign::<Blake2b512, OsRng>(k, &ring, None, &message).unwrap();
        let result = BLSAG::link(&signature_1, &signature_2);
        assert!(result);
    }
}
