#![no_std]
#![cfg(feature = "no_std")]

extern crate alloc;

use alloc::vec::Vec;
use nazgul::sag::SAG;
use nazgul::blsag::BLSAG;
use nazgul::clsag::CLSAG;
use nazgul::dlsag::DLSAG;
use nazgul::mlsag::MLSAG;
use nazgul::mdlsag::MDLSAG;
use nazgul::traits::{Sign, Verify, Link};

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

// Add similar no_std tests for other signature schemes... 