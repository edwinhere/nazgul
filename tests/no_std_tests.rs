#![no_std]
#![cfg(feature = "no_std")]

extern crate alloc;

use alloc::vec::Vec;
use nazgul::blsag::BLSAG;
use nazgul::clsag::CLSAG;
use nazgul::dlsag::DLSAG;
use nazgul::mlsag::MLSAG;
use nazgul::sag::SAG;
use nazgul::traits::{Link, Sign, Verify};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use sha2::Sha512;

#[test]
fn test_sag_no_std() {
    let mut csprng = OsRng;
    let k: Scalar = Scalar::random(&mut csprng);
    let secret_index = 1;
    let n = 2;
    let ring: Vec<RistrettoPoint> = (0..(n - 1))
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();
    let message: Vec<u8> = b"This is the message".iter().cloned().collect();

    let signature = SAG::sign::<Sha512, OsRng>(k, ring.clone(), secret_index, &message);
    let result = SAG::verify::<Sha512>(signature, &message);
    assert!(result);
}

#[test]
fn test_blsag_no_std() {
    let mut csprng = OsRng;
    let k: Scalar = Scalar::random(&mut csprng);
    let secret_index = 1;
    let n = 2;
    let ring: Vec<RistrettoPoint> = (0..(n - 1))
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();
    let message: Vec<u8> = b"This is the message".iter().cloned().collect();

    let signature = BLSAG::sign::<Sha512, OsRng>(k, ring.clone(), secret_index, &message);
    let result = BLSAG::verify::<Sha512>(signature.clone(), &message);
    assert!(result);

    // Test linking
    let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
    let signature2 = BLSAG::sign::<Sha512, OsRng>(k, ring.clone(), secret_index, &another_message);
    let link_result = BLSAG::link(signature, signature2);
    assert!(link_result);
}

#[test]
fn test_clsag_no_std() {
    let mut csprng = OsRng;
    let secret_index = 1;
    let nr = 2;
    let nc = 2;
    let ks: Vec<Scalar> = (0..nc).map(|_| Scalar::random(&mut csprng)).collect();
    let ring: Vec<Vec<RistrettoPoint>> = (0..(nr - 1))
        .map(|_| {
            (0..nc)
                .map(|_| RistrettoPoint::random(&mut csprng))
                .collect()
        })
        .collect();
    let message: Vec<u8> = b"This is the message".iter().cloned().collect();

    let signature = CLSAG::sign::<Sha512, OsRng>(ks.clone(), ring.clone(), secret_index, &message);
    let result = CLSAG::verify::<Sha512>(signature.clone(), &message);
    assert!(result);

    // Test linking
    let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
    let signature2 = CLSAG::sign::<Sha512, OsRng>(ks, ring.clone(), secret_index, &another_message);
    let link_result = CLSAG::link(signature, signature2);
    assert!(link_result);
}

#[test]
fn test_dlsag_no_std() {
    let mut csprng = OsRng;
    let k: (Scalar, RistrettoPoint, Scalar) = (
        Scalar::random(&mut csprng),
        RistrettoPoint::random(&mut csprng),
        Scalar::random(&mut csprng),
    );
    let other_k = (k.1, k.0, k.2);
    let secret_index = 1;
    let n = 2;
    let ring: Vec<(RistrettoPoint, RistrettoPoint, Scalar)> = (0..(n - 1))
        .map(|_| {
            (
                RistrettoPoint::random(&mut csprng),
                RistrettoPoint::random(&mut csprng),
                Scalar::random(&mut csprng),
            )
        })
        .collect();
    let message: Vec<u8> = b"This is the message".iter().cloned().collect();

    let signature = DLSAG::sign::<Sha512, OsRng>(k, ring.clone(), secret_index, &message);
    let result = DLSAG::verify::<Sha512>(signature.clone(), &message);
    assert!(result);

    // Test other end of channel
    let signature2 = DLSAG::sign::<Sha512, OsRng>(other_k, ring.clone(), secret_index, &message);
    let result2 = DLSAG::verify::<Sha512>(signature2.clone(), &message);
    assert!(result2);

    // Test linking
    let link_result = DLSAG::link(signature, signature2);
    assert!(link_result);
}

#[test]
fn test_mlsag_no_std() {
    let mut csprng = OsRng;
    let secret_index = 1;
    let nr = 2;
    let nc = 2;
    let ks: Vec<Scalar> = (0..nc).map(|_| Scalar::random(&mut csprng)).collect();
    let ring: Vec<Vec<RistrettoPoint>> = (0..(nr - 1))
        .map(|_| {
            (0..nc)
                .map(|_| RistrettoPoint::random(&mut csprng))
                .collect()
        })
        .collect();
    let message: Vec<u8> = b"This is the message".iter().cloned().collect();

    let signature = MLSAG::sign::<Sha512, OsRng>(ks.clone(), ring.clone(), secret_index, &message);
    let result = MLSAG::verify::<Sha512>(signature.clone(), &message);
    assert!(result);

    // Test linking
    let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
    let signature2 = MLSAG::sign::<Sha512, OsRng>(ks, ring.clone(), secret_index, &another_message);
    let link_result = MLSAG::link(signature, signature2);
    assert!(link_result);
}
