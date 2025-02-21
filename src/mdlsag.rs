use crate::traits::{KeyImageGen, Link, Sign, Verify};
use crate::prelude::*;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use curve25519_dalek::traits::MultiscalarMul;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Multilayer Dual Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups
///
/// [DLSAG: Non-Interactive Refund Transactions For Interoperable Payment Channels in Monero](https://eprint.iacr.org/2019/595.pdf)
///
/// This is a a novel linkable ring signature scheme that enables for the
/// first time refund transactions natively in Monero
///
/// Read the paper on how to use it to implement payment channels.
///
/// Please read tests at the bottom of the source code for this module for
/// examples on how to use it
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone)]
pub struct MDLSAG {
    pub challenge: Scalar,
    pub responses: Vec<Vec<Scalar>>,
    pub ring: Vec<Vec<(RistrettoPoint, RistrettoPoint, Scalar)>>,
    pub key_images: Vec<RistrettoPoint>,
    pub b: bool,
}

impl KeyImageGen<Vec<(Scalar, RistrettoPoint, Scalar)>, Vec<RistrettoPoint>> for MDLSAG {
    /// Some signature schemes require the key images to be signed as well.
    /// Use this method to generate them
    fn generate_key_image<Hash: Digest<OutputSize = U64> + Clone + Default>(
        ks: Vec<(Scalar, RistrettoPoint, Scalar)>,
    ) -> Vec<RistrettoPoint> {
        let nc = ks.len();

        let k_points: Vec<(RistrettoPoint, RistrettoPoint, Scalar)> = ks
            .iter()
            .map(|k| (k.0 * constants::RISTRETTO_BASEPOINT_POINT, k.1, k.2))
            .collect();

        let key_images: Vec<RistrettoPoint> = (0..nc)
            .map(|j| {
                ks[j].2
                    * ks[j].0
                    * RistrettoPoint::from_hash(
                        Hash::default().chain_update(k_points[j].1.compress().as_bytes()),
                    )
            })
            .collect();

        return key_images;
    }
}

impl KeyImageGen<Vec<(RistrettoPoint, Scalar, Scalar)>, Vec<RistrettoPoint>> for MDLSAG {
    /// Some signature schemes require the key images to be signed as well.
    /// Use this method to generate them
    fn generate_key_image<Hash: Digest<OutputSize = U64> + Clone + Default>(
        ks: Vec<(RistrettoPoint, Scalar, Scalar)>,
    ) -> Vec<RistrettoPoint> {
        let nc = ks.len();

        let k_points: Vec<(RistrettoPoint, RistrettoPoint, Scalar)> = ks
            .iter()
            .map(|k| (k.0, k.1 * constants::RISTRETTO_BASEPOINT_POINT, k.2))
            .collect();

        let key_images: Vec<RistrettoPoint> = (0..nc)
            .map(|j| {
                ks[j].2
                    * ks[j].1
                    * RistrettoPoint::from_hash(
                        Hash::default().chain_update(k_points[j].0.compress().as_bytes()),
                    )
            })
            .collect();

        return key_images;
    }
}

impl Sign<Vec<(Scalar, RistrettoPoint, Scalar)>, Vec<Vec<(RistrettoPoint, RistrettoPoint, Scalar)>>>
    for MDLSAG
{
    /// To sign you need `k` your private key, and `ring` which is the public keys of everyone
    /// except you. You are signing the `message`
    ///
    /// The private key `k` in this case is your private key, the public key of the other end of
    /// the channel and a random bitstring generated by hashing-to-scalar: the transaction ID, and
    /// output index.
    ///
    /// The ring contains public key pairs from the blockchain together with their random
    /// bitstrings as mentioned above.
    fn sign<
        Hash: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        ks: Vec<(Scalar, RistrettoPoint, Scalar)>,
        mut ring: Vec<Vec<(RistrettoPoint, RistrettoPoint, Scalar)>>,
        secret_index: usize,
        message: &Vec<u8>,
    ) -> MDLSAG {
        let mut csprng = CSPRNG::default();

        // Row count of matrix
        let nr = ring.len() + 1;
        // Column count of matrix
        let nc = ring[0].len();

        //Provers public keys
        let k_points: Vec<(RistrettoPoint, RistrettoPoint, Scalar)> = ks
            .iter()
            .map(|k| (k.0 * constants::RISTRETTO_BASEPOINT_POINT, k.1, k.2))
            .collect();

        let key_images: Vec<RistrettoPoint> = MDLSAG::generate_key_image::<Hash>(ks.clone());

        ring.insert(secret_index, k_points.clone());

        let a: Vec<Scalar> = (0..nc).map(|_| Scalar::random(&mut csprng)).collect();

        let mut rs: Vec<Vec<Scalar>> = (0..nr)
            .map(|_| (0..nc).map(|_| Scalar::random(&mut csprng)).collect())
            .collect();

        let mut cs: Vec<Scalar> = (0..nr).map(|_| Scalar::ZERO).collect();

        // Hash of message is shared by all challenges H_n(m, ....)
        let mut message_hash = Hash::default();

        message_hash.update(message);

        let mut hashes: Vec<Hash> = (0..nr).map(|_| message_hash.clone()).collect();

        for j in 0..nc {
            hashes[(secret_index + 1) % nr].update(
                (a[j] * constants::RISTRETTO_BASEPOINT_POINT)
                    .compress()
                    .as_bytes(),
            );
            hashes[(secret_index + 1) % nr].update(
                (a[j]
                    * ring[secret_index][j].2
                    * RistrettoPoint::from_hash(
                        Hash::default().chain_update(k_points[j].1.compress().as_bytes()),
                    ))
                .compress()
                .as_bytes(),
            );
        }
        cs[(secret_index + 1) % nr] = Scalar::from_hash(hashes[(secret_index + 1) % nr].clone());

        let mut i = (secret_index + 1) % nr;

        loop {
            for j in 0..nc {
                hashes[(i + 1) % nr].update(
                    RistrettoPoint::multiscalar_mul(
                        &[rs[i % nr][j], cs[i % nr]],
                        &[
                            constants::RISTRETTO_BASEPOINT_POINT,
                            ring[i % nr][j].0
                        ]
                    )
                        .compress()
                        .as_bytes(),
                );
                hashes[(i + 1) % nr].update(
                    RistrettoPoint::multiscalar_mul(
                        &[rs[i % nr][j], cs[i % nr]],
                        &[
                            ring[i % nr][j].2 * RistrettoPoint::from_hash(
                                Hash::default().chain_update(
                                    ring[i % nr][j].1.compress().as_bytes()),
                            ),
                            key_images[j]
                        ]
                    )
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
            rs[secret_index][j] = a[j] - (cs[secret_index] * ks[j].0);
        }

        return MDLSAG {
            challenge: cs[0],
            responses: rs,
            ring: ring,
            key_images: key_images,
            b: false,
        };
    }
}

impl Sign<Vec<(RistrettoPoint, Scalar, Scalar)>, Vec<Vec<(RistrettoPoint, RistrettoPoint, Scalar)>>>
    for MDLSAG
{
    /// To sign you need `k` your private key, and `ring` which is the public keys of everyone
    /// except you. You are signing the `message`
    ///
    /// The private key `k` in this case is your private key, the public key of the other end of
    /// the channel and a random bitstring generated by hashing-to-scalar: the transaction ID, and
    /// output index.
    ///
    /// The ring contains public key pairs from the blockchain together with their random
    /// bitstrings as mentioned above.
    fn sign<
        Hash: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        ks: Vec<(RistrettoPoint, Scalar, Scalar)>,
        mut ring: Vec<Vec<(RistrettoPoint, RistrettoPoint, Scalar)>>,
        secret_index: usize,
        message: &Vec<u8>,
    ) -> MDLSAG {
        let mut csprng = CSPRNG::default();

        // Row count of matrix
        let nr = ring.len() + 1;
        // Column count of matrix
        let nc = ring[0].len();

        //Provers public keys
        let k_points: Vec<(RistrettoPoint, RistrettoPoint, Scalar)> = ks
            .iter()
            .map(|k| (k.0, k.1 * constants::RISTRETTO_BASEPOINT_POINT, k.2))
            .collect();

        let key_images: Vec<RistrettoPoint> = MDLSAG::generate_key_image::<Hash>(ks.clone());

        ring.insert(secret_index, k_points.clone());

        let a: Vec<Scalar> = (0..nc).map(|_| Scalar::random(&mut csprng)).collect();

        let mut rs: Vec<Vec<Scalar>> = (0..nr)
            .map(|_| (0..nc).map(|_| Scalar::random(&mut csprng)).collect())
            .collect();

        let mut cs: Vec<Scalar> = (0..nr).map(|_| Scalar::ZERO).collect();

        // Hash of message is shared by all challenges H_n(m, ....)
        let mut message_hash = Hash::default();

        message_hash.update(message);

        let mut hashes: Vec<Hash> = (0..nr).map(|_| message_hash.clone()).collect();

        for j in 0..nc {
            hashes[(secret_index + 1) % nr].update(
                (a[j] * constants::RISTRETTO_BASEPOINT_POINT)
                    .compress()
                    .as_bytes(),
            );
            hashes[(secret_index + 1) % nr].update(
                (a[j]
                    * ring[secret_index][j].2
                    * RistrettoPoint::from_hash(
                        Hash::default().chain_update(k_points[j].0.compress().as_bytes()),
                    ))
                .compress()
                .as_bytes(),
            );
        }
        cs[(secret_index + 1) % nr] = Scalar::from_hash(hashes[(secret_index + 1) % nr].clone());

        let mut i = (secret_index + 1) % nr;

        loop {
            for j in 0..nc {
                hashes[(i + 1) % nr].update(
                    RistrettoPoint::multiscalar_mul(
                        &[rs[i % nr][j], cs[i % nr]],
                        &[
                            constants::RISTRETTO_BASEPOINT_POINT,
                            ring[i % nr][j].1
                        ]
                    )
                        .compress()
                        .as_bytes(),
                );
                hashes[(i + 1) % nr].update(
                    RistrettoPoint::multiscalar_mul(
                        &[rs[i % nr][j], cs[i % nr]],
                        &[
                            ring[i % nr][j].2 * RistrettoPoint::from_hash(
                                Hash::default().chain_update(
                                    ring[i % nr][j].0.compress().as_bytes()
                                )
                            ),
                            key_images[j]
                        ]
                    )
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
            rs[secret_index][j] = a[j] - (cs[secret_index] * ks[j].1);
        }

        return MDLSAG {
            challenge: cs[0],
            responses: rs,
            ring: ring,
            key_images: key_images,
            b: true,
        };
    }
}

impl Verify for MDLSAG {
    /// To verify a `signature` you need the `message` too
    fn verify<Hash: Digest<OutputSize = U64> + Clone + Default>(
        signature: MDLSAG,
        message: &Vec<u8>,
    ) -> bool {
        let mut reconstructed_c: Scalar = signature.challenge;
        // Row count of matrix
        let nr = signature.ring.len();
        // Column count of matrix
        let nc = signature.ring[0].len();
        for _i in 0..nr {
            let mut h: Hash = Hash::default();
            h.update(message);

            for j in 0..nc {
                if signature.b {
                    h.update(
                        RistrettoPoint::multiscalar_mul(
                            &[signature.responses[_i][j], reconstructed_c],
                            &[
                                constants::RISTRETTO_BASEPOINT_POINT,
                                signature.ring[_i][j].1
                            ]
                        )
                            .compress()
                            .as_bytes(),
                    );

                    h.update(
                        RistrettoPoint::multiscalar_mul(
                            &[signature.responses[_i][j], reconstructed_c],
                            &[
                                signature.ring[_i][j].2 * RistrettoPoint::from_hash(
                                    Hash::default().chain_update(
                                        signature.ring[_i][j].0.compress().as_bytes()
                                    )
                                ),
                                signature.key_images[j]
                            ])
                            .compress()
                            .as_bytes(),
                    );
                } else {
                    h.update(
                        RistrettoPoint::multiscalar_mul(
                            &[signature.responses[_i][j], reconstructed_c],
                            &[constants::RISTRETTO_BASEPOINT_POINT, signature.ring[_i][j].0
                            ]
                        )
                            .compress()
                            .as_bytes(),
                    );

                    h.update(
                        RistrettoPoint::multiscalar_mul(
                            &[signature.responses[_i][j], reconstructed_c],
                            &[
                                signature.ring[_i][j].2 * RistrettoPoint::from_hash(
                                    Hash::default().chain_update(
                                        signature.ring[_i][j].1.compress().as_bytes()
                                    )
                                ),
                                signature.key_images[j]
                            ]
                        )
                            .compress()
                            .as_bytes(),
                    );
                }
            }
            reconstructed_c = Scalar::from_hash(h);
        }

        return signature.challenge == reconstructed_c;
    }
}

impl Link for MDLSAG {
    /// This is for linking two signatures and checking if they are signed by the same person
    fn link(signature_1: MDLSAG, signature_2: MDLSAG) -> bool {
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
    fn mdlsag() {
        let mut csprng = OsRng::default();

        let secret_index = 1;
        let nr = 2;
        let nc = 2;

        let ks: Vec<(Scalar, RistrettoPoint, Scalar)> = (0..nc)
            .map(|_| {
                (
                    Scalar::random(&mut csprng),         // The prover's private key
                    RistrettoPoint::random(&mut csprng), // The public key of the other end of the channel
                    // According to the paper this should be a random
                    // bitstring generated by hashing transaction ID, and output index.
                    // It is simulated here using a random bitstring
                    Scalar::random(&mut csprng),
                )
            })
            .collect();

        let other_ks: Vec<(RistrettoPoint, Scalar, Scalar)> =
            ks.iter().map(|k| (k.1, k.0, k.2)).collect();

        // Simulate randomly chosen Public keys (Prover will insert her public keys here later)
        let ring: Vec<Vec<(RistrettoPoint, RistrettoPoint, Scalar)>> = (0..(nr - 1)) // Prover is going to add her key into this mix
            .map(|_| {
                (0..nc)
                    .map(|_| {
                        (
                            RistrettoPoint::random(&mut csprng),
                            RistrettoPoint::random(&mut csprng),
                            Scalar::random(&mut csprng),
                        )
                    })
                    .collect()
            })
            .collect();

        let message: Vec<u8> = b"This is the message".iter().cloned().collect();

        {
            let signature =
                MDLSAG::sign::<Sha512, OsRng>(ks.clone(), ring.clone(), secret_index, &message);
            let result = MDLSAG::verify::<Sha512>(signature, &message);
            assert!(result);
        }

        {
            let signature =
                MDLSAG::sign::<Keccak512, OsRng>(ks.clone(), ring.clone(), secret_index, &message);
            let result = MDLSAG::verify::<Keccak512>(signature, &message);
            assert!(result);
        }

        {
            let signature =
                MDLSAG::sign::<Blake2b512, OsRng>(ks.clone(), ring.clone(), secret_index, &message);
            let result = MDLSAG::verify::<Blake2b512>(signature, &message);
            assert!(result);
        }

        {
            let signature = MDLSAG::sign::<Sha512, OsRng>(
                other_ks.clone(),
                ring.clone(),
                secret_index,
                &message,
            );
            let result = MDLSAG::verify::<Sha512>(signature, &message);
            assert!(result);
        }

        {
            let signature = MDLSAG::sign::<Keccak512, OsRng>(
                other_ks.clone(),
                ring.clone(),
                secret_index,
                &message,
            );
            let result = MDLSAG::verify::<Keccak512>(signature, &message);
            assert!(result);
        }

        {
            let signature = MDLSAG::sign::<Blake2b512, OsRng>(
                other_ks.clone(),
                ring.clone(),
                secret_index,
                &message,
            );
            let result = MDLSAG::verify::<Blake2b512>(signature, &message);
            assert!(result);
        }

        let another_ring: Vec<Vec<(RistrettoPoint, RistrettoPoint, Scalar)>> =
            (0..(nr - 1)) // Prover is going to add her key into this mix
                .map(|_| {
                    (0..nc)
                        .map(|_| {
                            (
                                RistrettoPoint::random(&mut csprng),
                                RistrettoPoint::random(&mut csprng),
                                Scalar::random(&mut csprng),
                            )
                        })
                        .collect()
                })
                .collect();
        let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
        let signature_1 = MDLSAG::sign::<Blake2b512, OsRng>(
            ks.clone(),
            another_ring.clone(),
            secret_index,
            &another_message,
        );
        let signature_2 =
            MDLSAG::sign::<Blake2b512, OsRng>(ks.clone(), ring.clone(), secret_index, &message);
        let signature_3 =
            MDLSAG::sign::<Blake2b512, OsRng>(other_ks.clone(), ring.clone(), secret_index, &message);
        let result_1 = MDLSAG::link(signature_1.clone(), signature_2);
        assert!(result_1);
        let result_2 = MDLSAG::link(signature_1.clone(), signature_3);
        assert!(result_2);
    }
}
