use nazgul::blsag::BLSAG;
use nazgul::error::SignatureError;
use nazgul::traits::{LinkRef, SignRef, VerifyRef};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore, OsRng};
use sha2::Sha512;

// ==============
// HELPER FUNCTIONS
// ==============

// Generates a random private key and its corresponding public key.
fn generate_keypair<R: RngCore + CryptoRng>(csprng: &mut R) -> (Scalar, RistrettoPoint) {
    let private_key = Scalar::random(csprng);
    let public_key = private_key * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    (private_key, public_key)
}

// Generates a ring of random public keys.
fn generate_ring<R: RngCore + CryptoRng>(csprng: &mut R, num_decoys: usize) -> Vec<RistrettoPoint> {
    (0..num_decoys)
        .map(|_| RistrettoPoint::random(csprng))
        .collect()
}

const MESSAGE: &[u8] = b"The owls are not what they seem.";

// ==============
// CORE FUNCTIONALITY TESTS
// ==============

#[test]
fn sign_and_verify_succeeds() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);
    let secret_index = 3;
    let num_decoys = 10;

    let mut ring = generate_ring(&mut csprng, num_decoys);
    ring.insert(secret_index, signer_public_key);

    let signature = BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring, MESSAGE).unwrap();

    assert!(BLSAG::verify::<Sha512>(&signature, &ring, MESSAGE));
}

#[test]
fn link_succeeds_for_same_signer() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);
    let secret_index = 2;
    let num_decoys = 4;

    let mut ring1 = generate_ring(&mut csprng, num_decoys);
    ring1.insert(secret_index, signer_public_key);

    let mut ring2 = generate_ring(&mut csprng, num_decoys);
    ring2.insert(secret_index, signer_public_key);

    let message2: &[u8] = b"A different message for the second signature.";

    let signature1 = BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring1, MESSAGE).unwrap();
    let signature2 = BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring2, message2).unwrap();

    assert!(BLSAG::link(&signature1, &signature2));
}

#[test]
fn link_fails_for_different_signers() {
    let mut csprng = OsRng;

    // Signer 1
    let (private_key1, public_key1) = generate_keypair(&mut csprng);
    let mut ring1 = generate_ring(&mut csprng, 5);
    ring1.insert(1, public_key1);
    let signature1 = BLSAG::sign::<Sha512, OsRng>(private_key1, &ring1, MESSAGE).unwrap();

    // Signer 2
    let (private_key2, public_key2) = generate_keypair(&mut csprng);
    let mut ring2 = generate_ring(&mut csprng, 5);
    ring2.insert(4, public_key2);
    let signature2 = BLSAG::sign::<Sha512, OsRng>(private_key2, &ring2, MESSAGE).unwrap();

    assert!(!BLSAG::link(&signature1, &signature2));
}

// ==============
// FAILURE PATH TESTS
// ==============

#[test]
fn verify_fails_with_wrong_message() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);
    let secret_index = 0;
    let mut ring = generate_ring(&mut csprng, 7);
    ring.insert(secret_index, signer_public_key);

    let signature = BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring, MESSAGE).unwrap();

    let wrong_message: &[u8] = b"This is not the message you are looking for.";
    assert!(!BLSAG::verify::<Sha512>(&signature, &ring, wrong_message));
}

// ==============
// SECURITY PROPERTY TESTS
// ==============

#[test]
fn sign_fails_if_signer_not_in_ring() {
    // Unforgeability Test: An attacker without a valid private key from the ring
    // should not be able to create a signature.
    let mut csprng = OsRng;
    let (attacker_private_key, _) = generate_keypair(&mut csprng);
    let num_decoys = 10;

    // The ring is composed entirely of decoys; the attacker's public key is not included.
    let ring = generate_ring(&mut csprng, num_decoys);

    // This call should fail because the public key corresponding to the private key
    // is not present in the ring.
    let result = BLSAG::sign::<Sha512, OsRng>(attacker_private_key, &ring, MESSAGE);
    assert!(matches!(result, Err(SignatureError::SignerNotFound)));
}

#[test]
fn verify_succeeds_for_every_ring_member() {
    // Anonymity Test: A signature should be valid regardless of the signer's
    // position in the ring, demonstrating signer ambiguity.
    let mut csprng = OsRng;
    let num_members = 5;

    // Create a set of keypairs for the ring members.
    let keypairs: Vec<(Scalar, RistrettoPoint)> =
        (0..num_members).map(|_| generate_keypair(&mut csprng)).collect();

    let ring: Vec<RistrettoPoint> = keypairs.iter().map(|(_, public_key)| *public_key).collect();

    // Iterate through each member, have them sign, and verify the signature.
    for (signer_private_key, _) in keypairs.iter() {
        let signature = BLSAG::sign::<Sha512, OsRng>(*signer_private_key, &ring, MESSAGE).unwrap();
        assert!(
            BLSAG::verify::<Sha512>(&signature, &ring, MESSAGE),
            "Verification failed for a valid signer from the ring"
        );
    }
}

#[test]
fn link_succeeds_for_same_signer_with_different_rings() {
    // Linkability Test: Two signatures from the same signer must be linkable,
    // even if the decoy sets (rings) are completely different.
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);

    // Create two different rings, but both contain the signer's public key.
    let mut ring1 = generate_ring(&mut csprng, 7);
    ring1.insert(3, signer_public_key);

    let mut ring2 = generate_ring(&mut csprng, 10);
    ring2.insert(8, signer_public_key);

    let message1: &[u8] = b"First message.";
    let message2: &[u8] = b"Second message.";

    let signature1 = BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring1, message1).unwrap();
    let signature2 = BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring2, message2).unwrap();

    assert!(
        BLSAG::link(&signature1, &signature2),
        "Linking failed for the same signer with different decoy rings."
    );
}

// #[test]
// fn verify_fails_with_tampered_challenge() {
//     let mut csprng = OsRng;
//     let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);
//     let secret_index = 1;
//     let mut ring = generate_ring(&mut csprng, 3);
//     ring.insert(secret_index, signer_public_key);

//     let mut signature = BLSAG::sign::<Sha512, OsRng>(signer_private_key.clone(), ring, secret_index, MESSAGE);

//     // Tamper with the challenge
//     signature.challenge = signature.challenge + Scalar::ONE;

//     assert!(!BLSAG::verify::<Sha512>(&signature, MESSAGE));
// }

// #[test]
// fn verify_fails_with_tampered_response() {
//     let mut csprng = OsRng;
//     let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);
//     let secret_index = 4;
//     let mut ring = generate_ring(&mut csprng, 5);
//     ring.insert(secret_index, signer_public_key);

//     let mut signature = BLSAG::sign::<Sha512, OsRng>(signer_private_key.clone(), ring, secret_index, MESSAGE);

//     // Tamper with one of the responses
//     signature.responses[2] = signature.responses[2] + Scalar::ONE;

//     assert!(!BLSAG::verify::<Sha512>(&signature, MESSAGE));
// }

// #[test]
// fn verify_fails_with_different_ring() {
//     let mut csprng = OsRng;
//     let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);
//     let secret_index = 2;
//     let mut ring = generate_ring(&mut csprng, 6);
//     ring.insert(secret_index, signer_public_key);

//     let mut signature = BLSAG::sign::<Sha512, OsRng>(signer_private_key.clone(), ring, secret_index, MESSAGE);

//     // Create a completely different ring for verification
//     let mut different_ring = generate_ring(&mut csprng, 6);
//     different_ring.insert(secret_index, signer_public_key);
//     signature.ring = different_ring;

//     assert!(!BLSAG::verify::<Sha512>(&signature, MESSAGE));
// }