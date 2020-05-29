use crate::traits::{KeyImageGen, Link, Sign, Verify};
use alloc::vec::Vec;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};

/// Multilayer Linkable Spontaneous Anonymous Group (MLSAG) signatures
/// > In order to sign transactions, one has to sign with multiple private keys. In
/// [this paper](https://web.getmonero.org/resources/research-lab/pubs/MRL-0005.pdf),
/// Shen Noether et al. describe a multi-layered generalization of the bLSAG signature
/// scheme applicable when we have a set of n · m keys
///
/// Please read tests at the bottom of the source code for this module for examples on how to use
/// it
pub struct MLSAG {
    challenge: Scalar,
    responses: Vec<Vec<Scalar>>,
    ring: Vec<Vec<RistrettoPoint>>,
    key_images: Vec<RistrettoPoint>,
}

impl KeyImageGen<Vec<Scalar>, Vec<RistrettoPoint>> for MLSAG {
    /// Some signature schemes require the key images to be signed as well.
    /// Use this method to generate them
    fn generate_key_image<Hash: Digest<OutputSize = U64> + Clone + Default>(
        ks: Vec<Scalar>,
    ) -> Vec<RistrettoPoint> {
        let nc = ks.len();

        let k_points: Vec<RistrettoPoint> = ks
            .iter()
            .map(|k| k * constants::RISTRETTO_BASEPOINT_POINT)
            .collect();

        let key_images: Vec<RistrettoPoint> = (0..nc)
            .map(|j| {
                ks[j]
                    * RistrettoPoint::from_hash(
                        Hash::default().chain(k_points[j].compress().as_bytes()),
                    )
            })
            .collect();

        return key_images;
    }
}

impl Sign<Vec<Scalar>, Vec<Vec<RistrettoPoint>>> for MLSAG {
    /// To sign you need `ks` which is the set of private keys you want to sign with. The `ring` contains
    /// public keys for everybody except you. Your public key will be inserted into it at random (secret)
    /// index. The `message` is what you are signing
    fn sign<
        Hash: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        ks: Vec<Scalar>,
        mut ring: Vec<Vec<RistrettoPoint>>,
        message: &Vec<u8>,
    ) -> MLSAG {
        let mut csprng = CSPRNG::default();

        // Row count of matrix
        let nr = ring.len() + 1;
        // Column count of matrix
        let nc = ring[0].len();

        //Provers public keys
        let k_points: Vec<RistrettoPoint> = ks
            .iter()
            .map(|k| k * constants::RISTRETTO_BASEPOINT_POINT)
            .collect();

        let key_images: Vec<RistrettoPoint> = MLSAG::generate_key_image::<Hash>(ks.clone());

        // This is the index where we hide our keys
        let secret_index = (csprng.next_u32() % nr as u32) as usize;

        ring.insert(secret_index, k_points.clone());

        let a: Vec<Scalar> = (0..nc).map(|_| Scalar::random(&mut csprng)).collect();

        let mut rs: Vec<Vec<Scalar>> = (0..nr)
            .map(|_| (0..nc).map(|_| Scalar::random(&mut csprng)).collect())
            .collect();

        let mut cs: Vec<Scalar> = (0..nr).map(|_| Scalar::zero()).collect();

        // Hash of message is shared by all challenges H_n(m, ....)
        let mut message_hash = Hash::default();

        message_hash.input(message);

        let mut hashes: Vec<Hash> = (0..nr).map(|_| message_hash.clone()).collect();

        for j in 0..nc {
            hashes[(secret_index + 1) % nr].input(
                (a[j] * constants::RISTRETTO_BASEPOINT_POINT)
                    .compress()
                    .as_bytes(),
            );
            hashes[(secret_index + 1) % nr].input(
                (a[j]
                    * RistrettoPoint::from_hash(
                        Hash::default().chain(k_points[j].compress().as_bytes()),
                    ))
                .compress()
                .as_bytes(),
            );
        }
        cs[(secret_index + 1) % nr] = Scalar::from_hash(hashes[(secret_index + 1) % nr].clone());

        let mut i = (secret_index + 1) % nr;

        loop {
            for j in 0..nc {
                hashes[(i + 1) % nr].input(
                    ((rs[i % nr][j] * constants::RISTRETTO_BASEPOINT_POINT)
                        + (cs[i % nr] * ring[i % nr][j]))
                        .compress()
                        .as_bytes(),
                );
                hashes[(i + 1) % nr].input(
                    ((rs[i % nr][j]
                        * RistrettoPoint::from_hash(
                            Hash::default().chain(ring[i % nr][j].compress().as_bytes()),
                        ))
                        + (cs[i % nr] * key_images[j]))
                        .compress()
                        .as_bytes(),
                );
            }
            cs[(i + 1) % nr] = Scalar::from_hash(hashes[(i + 1) % nr].clone());

            if secret_index >= 1 && i % nr == (secret_index - 1) % nr {
                break;
            } else if secret_index == 0 && i % nr == nr - 1 {
                break;
            } else {
                i = (i + 1) % nr;
            }
        }

        for j in 0..nc {
            rs[secret_index][j] = a[j] - (cs[secret_index] * ks[j]);
        }

        return MLSAG {
            challenge: cs[0],
            responses: rs,
            ring: ring,
            key_images: key_images,
        };
    }
}

impl Verify for MLSAG {
    /// To verify a `signature` you need the `message` too
    fn verify<Hash: Digest<OutputSize = U64> + Clone + Default>(
        signature: MLSAG,
        message: &Vec<u8>,
    ) -> bool {
        let mut reconstructed_c: Scalar = signature.challenge;
        // Row count of matrix
        let nr = signature.ring.len();
        // Column count of matrix
        let nc = signature.ring[0].len();
        for _i in 0..nr {
            let mut h: Hash = Hash::default();
            h.input(message);

            for j in 0..nc {
                h.input(
                    ((signature.responses[_i][j] * constants::RISTRETTO_BASEPOINT_POINT)
                        + (reconstructed_c * signature.ring[_i][j]))
                        .compress()
                        .as_bytes(),
                );

                h.input(
                    (signature.responses[_i][j]
                        * RistrettoPoint::from_hash(
                            Hash::default().chain(signature.ring[_i][j].compress().as_bytes()),
                        )
                        + (reconstructed_c * signature.key_images[j]))
                        .compress()
                        .as_bytes(),
                );
            }
            reconstructed_c = Scalar::from_hash(h);
        }

        return signature.challenge == reconstructed_c;
    }
}

impl Link for MLSAG {
    /// This is for linking two signatures and checking if they are signed by the same person
    fn link(signature_1: MLSAG, signature_2: MLSAG) -> bool {
        let mut vec: Vec<[u8; 32]> = Vec::new();
        vec.append(
            &mut signature_1
                .key_images
                .iter()
                .map(|x| x.compress().to_bytes())
                .collect(),
        );
        vec.append(
            &mut signature_2
                .key_images
                .iter()
                .map(|x| x.compress().to_bytes())
                .collect(),
        );
        vec.sort_unstable();
        return vec.iter().zip(vec.iter().skip(1)).any(|(a, b)| a == b);
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
    fn mlsag() {
        let mut csprng = OsRng::default();

        let nr = 2;
        let nc = 2;

        let ks: Vec<Scalar> = (0..nc).map(|_| Scalar::random(&mut csprng)).collect();

        // Simulate randomly chosen Public keys (Prover will insert her public keys here later)
        let ring: Vec<Vec<RistrettoPoint>> = (0..(nr - 1)) // Prover is going to add her key into this mix
            .map(|_| {
                (0..nc)
                    .map(|_| RistrettoPoint::random(&mut csprng))
                    .collect()
            })
            .collect();
        let message: Vec<u8> = b"This is the message".iter().cloned().collect();

        {
            let signature = MLSAG::sign::<Sha512, OsRng>(ks.clone(), ring.clone(), &message);
            let result = MLSAG::verify::<Sha512>(signature, &message);
            assert!(result);
        }

        {
            let signature = MLSAG::sign::<Keccak512, OsRng>(ks.clone(), ring.clone(), &message);
            let result = MLSAG::verify::<Keccak512>(signature, &message);
            assert!(result);
        }

        {
            let signature = MLSAG::sign::<Blake2b, OsRng>(ks.clone(), ring.clone(), &message);
            let result = MLSAG::verify::<Blake2b>(signature, &message);
            assert!(result);
        }

        let another_ring: Vec<Vec<RistrettoPoint>> = (0..(nr - 1)) // Prover is going to add her key into this mix
            .map(|_| {
                (0..nc)
                    .map(|_| RistrettoPoint::random(&mut csprng))
                    .collect()
            })
            .collect();
        let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
        let signature_1 =
            MLSAG::sign::<Blake2b, OsRng>(ks.clone(), another_ring.clone(), &another_message);
        let signature_2 = MLSAG::sign::<Blake2b, OsRng>(ks.clone(), ring.clone(), &message);
        let result = MLSAG::link(signature_1, signature_2);
        assert!(result);
    }
}
