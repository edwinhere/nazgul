use nazgul::blsag::BLSAG;
use nazgul::error::SignatureError;
use nazgul::keys::Keypair;
use nazgul::ring::Ring;
use nazgul::traits::{LinkRef, SignRef, VerifyRef};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha512;

// ==============
// HELPER FUNCTIONS
// ==============

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
    let keypair = Keypair::generate(&mut csprng);
    let num_decoys = 10;

    let mut public_keys = generate_ring(&mut csprng, num_decoys);
    public_keys.push(*keypair.public_key());
    let ring = Ring::new(public_keys);

    let signature =
        BLSAG::sign::<Sha512, OsRng>(*keypair.private_key(), &ring, None, MESSAGE).unwrap();

    assert!(BLSAG::verify::<Sha512>(&signature, &ring, None, MESSAGE));
}

#[test]
fn link_succeeds_for_same_signer() {
    let mut csprng = OsRng;
    let keypair = Keypair::generate(&mut csprng);
    let num_decoys = 4;

    let mut public_keys1 = generate_ring(&mut csprng, num_decoys);
    public_keys1.push(*keypair.public_key());
    let ring1 = Ring::new(public_keys1);

    let mut public_keys2 = generate_ring(&mut csprng, num_decoys);
    public_keys2.push(*keypair.public_key());
    let ring2 = Ring::new(public_keys2);

    let message2: &[u8] = b"A different message for the second signature.";

    let signature1 =
        BLSAG::sign::<Sha512, OsRng>(*keypair.private_key(), &ring1, None, MESSAGE).unwrap();
    let signature2 =
        BLSAG::sign::<Sha512, OsRng>(*keypair.private_key(), &ring2, None, message2).unwrap();

    assert!(BLSAG::link(&signature1, &signature2));
}

#[test]
fn link_fails_for_different_signers() {
    let mut csprng = OsRng;

    // Signer 1
    let keypair1 = Keypair::generate(&mut csprng);
    let mut public_keys1 = generate_ring(&mut csprng, 5);
    public_keys1.push(*keypair1.public_key());
    let ring1 = Ring::new(public_keys1);
    let signature1 =
        BLSAG::sign::<Sha512, OsRng>(*keypair1.private_key(), &ring1, None, MESSAGE).unwrap();

    // Signer 2
    let keypair2 = Keypair::generate(&mut csprng);
    let mut public_keys2 = generate_ring(&mut csprng, 5);
    public_keys2.push(*keypair2.public_key());
    let ring2 = Ring::new(public_keys2);
    let signature2 =
        BLSAG::sign::<Sha512, OsRng>(*keypair2.private_key(), &ring2, None, MESSAGE).unwrap();

    assert!(!BLSAG::link(&signature1, &signature2));
}

// ==============
// FAILURE PATH TESTS
// ==============

#[test]
fn verify_fails_with_wrong_message() {
    let mut csprng = OsRng;
    let keypair = Keypair::generate(&mut csprng);
    let num_decoys = 7;

    let mut public_keys = generate_ring(&mut csprng, num_decoys);
    public_keys.push(*keypair.public_key());
    let ring = Ring::new(public_keys);

    let signature =
        BLSAG::sign::<Sha512, OsRng>(*keypair.private_key(), &ring, None, MESSAGE).unwrap();

    let wrong_message: &[u8] = b"This is not the message you are looking for.";
    assert!(!BLSAG::verify::<Sha512>(
        &signature,
        &ring,
        None,
        wrong_message
    ));
}

// ==============
// SECURITY PROPERTY TESTS
// ==============

#[test]
fn sign_fails_if_signer_not_in_ring() {
    // Unforgeability Test: An attacker without a valid private key from the ring
    // should not be able to create a signature.
    let mut csprng = OsRng;
    let attacker_keypair = Keypair::generate(&mut csprng);
    let num_decoys = 10;

    // The ring is composed entirely of decoys; the attacker's public key is not included.
    let decoys = generate_ring(&mut csprng, num_decoys);
    let ring = Ring::new(decoys);

    // This call should fail because the public key corresponding to the private key
    // is not present in the ring.
    let result =
        BLSAG::sign::<Sha512, OsRng>(*attacker_keypair.private_key(), &ring, None, MESSAGE);
    assert!(matches!(result, Err(SignatureError::SignerNotFound)));
}

#[test]
fn verify_succeeds_for_every_ring_member() {
    // Anonymity Test: A signature should be valid regardless of the signer's
    // position in the ring, demonstrating signer ambiguity.
    let mut csprng = OsRng;
    let num_members = 5;

    // Create a set of keypairs for the ring members.
    let keypairs: Vec<Keypair> = (0..num_members)
        .map(|_| Keypair::generate(&mut csprng))
        .collect();

    let public_keys: Vec<RistrettoPoint> = keypairs
        .iter()
        .map(|keypair| *keypair.public_key())
        .collect();
    let ring = Ring::new(public_keys);

    // Iterate through each member, have them sign, and verify the signature.
    for keypair in keypairs.iter() {
        let signature =
            BLSAG::sign::<Sha512, OsRng>(*keypair.private_key(), &ring, None, MESSAGE).unwrap();
        assert!(
            BLSAG::verify::<Sha512>(&signature, &ring, None, MESSAGE),
            "Verification failed for a valid signer from the ring"
        );
    }
}

#[test]
fn link_succeeds_for_same_signer_with_different_rings() {
    // Linkability Test: Two signatures from the same signer must be linkable,
    // even if the decoy sets (rings) are completely different.
    let mut csprng = OsRng;
    let keypair = Keypair::generate(&mut csprng);

    // Create two different rings, but both contain the signer's public key.
    let mut public_keys1 = generate_ring(&mut csprng, 7);
    public_keys1.push(*keypair.public_key());
    let ring1 = Ring::new(public_keys1);

    let mut public_keys2 = generate_ring(&mut csprng, 10);
    public_keys2.push(*keypair.public_key());
    let ring2 = Ring::new(public_keys2);

    let message1: &[u8] = b"First message.";
    let message2: &[u8] = b"Second message.";

    let signature1 =
        BLSAG::sign::<Sha512, OsRng>(*keypair.private_key(), &ring1, None, message1).unwrap();
    let signature2 =
        BLSAG::sign::<Sha512, OsRng>(*keypair.private_key(), &ring2, None, message2).unwrap();

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

#[test]
fn sign_and_verify_with_precomputation_succeeds() {
    let mut csprng = OsRng;
    let keypair = Keypair::generate(&mut csprng);
    let num_decoys = 50; // Use a slightly larger ring to make precomputation more meaningful

    let mut public_keys = generate_ring(&mut csprng, num_decoys);
    public_keys.push(*keypair.public_key());
    let ring = Ring::new(public_keys);

    // 1. Generate and verify the precomputed data
    let precomputed_data = ring.precompute::<Sha512>();
    assert!(precomputed_data.verify::<Sha512>(&ring));

    // 2. Sign using the precomputed data
    let signature = BLSAG::sign::<Sha512, OsRng>(
        *keypair.private_key(),
        &ring,
        Some(&precomputed_data),
        MESSAGE,
    )
    .unwrap();

    // 3. Verify the signature using the precomputed data
    assert!(
        BLSAG::verify::<Sha512>(&signature, &ring, Some(&precomputed_data), MESSAGE),
        "Verification with precomputation failed"
    );

    // 4. Verify the same signature WITHOUT the precomputed data
    assert!(
        BLSAG::verify::<Sha512>(&signature, &ring, None, MESSAGE),
        "Verification without precomputation failed for a signature created with it"
    );

    // 5. Verify that incorrect precomputed data fails
    let other_ring = Ring::new(generate_ring(&mut csprng, num_decoys + 1));
    let bad_precomputed_data = other_ring.precompute::<Sha512>();
    assert!(
        !precomputed_data.verify::<Sha512>(&other_ring),
        "Verification of precomputed data should fail for the wrong ring"
    );
    assert!(
        !BLSAG::verify::<Sha512>(&signature, &ring, Some(&bad_precomputed_data), MESSAGE),
        "Verification should fail with incorrect precomputed data"
    );
}
