#![cfg(feature = "serde-derive")]

use nazgul::blsag::BLSAG;
use nazgul::clsag::CLSAG;
use nazgul::dlsag::DLSAG;
use nazgul::mdlsag::MDLSAG;
use nazgul::mlsag::MLSAG;
use nazgul::sag::SAG;
use nazgul::traits::{Sign, Verify};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use sha2::Sha512;

#[test]
fn test_sag_serde() {
    let mut csprng = OsRng;
    let k: Scalar = Scalar::random(&mut csprng);
    let secret_index = 1;
    let n = 2;
    let ring: Vec<RistrettoPoint> = (0..(n - 1))
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();
    let message: Vec<u8> = b"This is the message".iter().cloned().collect();

    let signature = SAG::sign::<Sha512, OsRng>(k, ring.clone(), secret_index, &message);

    // Serialize to JSON
    let serialized = serde_json::to_string(&signature).unwrap();

    // Deserialize from JSON
    let deserialized: SAG = serde_json::from_str(&serialized).unwrap();

    // Verify the deserialized signature works
    let result = SAG::verify::<Sha512>(deserialized, &message);
    assert!(result);
}

#[test]
fn test_blsag_serde() {
    let mut csprng = OsRng;
    let k: Scalar = Scalar::random(&mut csprng);
    let secret_index = 1;
    let n = 2;
    let ring: Vec<RistrettoPoint> = (0..(n - 1))
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();
    let message: Vec<u8> = b"This is the message".iter().cloned().collect();

    let signature = BLSAG::sign::<Sha512, OsRng>(k, ring.clone(), secret_index, &message);

    let serialized = serde_json::to_string(&signature).unwrap();
    let deserialized: BLSAG = serde_json::from_str(&serialized).unwrap();

    let result = BLSAG::verify::<Sha512>(deserialized, &message);
    assert!(result);
}

#[test]
fn test_clsag_serde() {
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

    let serialized = serde_json::to_string(&signature).unwrap();
    let deserialized: CLSAG = serde_json::from_str(&serialized).unwrap();

    let result = CLSAG::verify::<Sha512>(deserialized, &message);
    assert!(result);
}

#[test]
fn test_dlsag_serde() {
    let mut csprng = OsRng;
    let k: (Scalar, RistrettoPoint, Scalar) = (
        Scalar::random(&mut csprng),
        RistrettoPoint::random(&mut csprng),
        Scalar::random(&mut csprng),
    );
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

    let serialized = serde_json::to_string(&signature).unwrap();
    let deserialized: DLSAG = serde_json::from_str(&serialized).unwrap();

    let result = DLSAG::verify::<Sha512>(deserialized, &message);
    assert!(result);
}

#[test]
fn test_mlsag_serde() {
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

    let serialized = serde_json::to_string(&signature).unwrap();
    let deserialized: MLSAG = serde_json::from_str(&serialized).unwrap();

    let result = MLSAG::verify::<Sha512>(deserialized, &message);
    assert!(result);
}

#[test]
fn test_mdlsag_serde() {
    let mut csprng = OsRng;
    let secret_index = 1;
    let nr = 2;
    let nc = 2;

    let ks: Vec<(Scalar, RistrettoPoint, Scalar)> = (0..nc)
        .map(|_| {
            (
                Scalar::random(&mut csprng),
                RistrettoPoint::random(&mut csprng),
                Scalar::random(&mut csprng),
            )
        })
        .collect();

    let ring: Vec<Vec<(RistrettoPoint, RistrettoPoint, Scalar)>> = (0..(nr - 1))
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

    let signature = MDLSAG::sign::<Sha512, OsRng>(ks.clone(), ring.clone(), secret_index, &message);

    let serialized = serde_json::to_string(&signature).unwrap();
    let deserialized: MDLSAG = serde_json::from_str(&serialized).unwrap();

    let result = MDLSAG::verify::<Sha512>(deserialized, &message);
    assert!(result);
}
