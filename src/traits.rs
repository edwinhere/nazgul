use crate::error::SignatureError;
use crate::ring::{PrecomputedRingData, Ring};
use digest::{generic_array::typenum::U64, Digest};
use rand_core::{CryptoRng, RngCore};

pub trait KeyImageGen<Secret, Point> {
    fn generate_key_image<Hash: Digest<OutputSize = U64> + Clone + Default>(k: Secret) -> Point;
}

pub trait Sign<Secret, Ring> {
    fn sign<
        Hash: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Secret,
        ring: Ring,
        secret_index: usize,
        message: &[u8],
    ) -> Self;
}

pub trait Verify {
    /// To verify a `signature` you need the `message` too
    fn verify<Hash: Digest<OutputSize = U64> + Clone + Default>(
        signature: Self,
        message: &[u8],
    ) -> bool;
}

pub trait Link {
    /// This is for linking two signatures and checking if they are signed by the same person
    fn link(signature_1: Self, signature_2: Self) -> bool;
}

// ================================================================================================
// Traits for passing by reference, intended for gradual adoption.
// ================================================================================================

pub trait VerifyRef {
    /// To verify a `signature` you need the `message` too. This trait passes the signature
    /// by reference.
    fn verify<Hash: Digest<OutputSize = U64> + Clone + Default>(
        signature: &Self,
        ring: &Ring,
        precomputed_data: Option<&PrecomputedRingData>,
        message: &[u8],
    ) -> bool;
}

pub trait LinkRef {
    /// This is for linking two signatures and checking if they are signed by the same person.
    /// This trait passes signatures by reference.
    fn link(signature_1: &Self, signature_2: &Self) -> bool;
}

pub trait SignRef<Secret> {
    fn sign<
        Hash: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Secret,
        ring: &Ring,
        precomputed_data: Option<&PrecomputedRingData>,
        message: &[u8],
    ) -> Result<Self, SignatureError>
    where
        Self: Sized;
}
