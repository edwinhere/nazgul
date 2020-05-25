use alloc::vec::Vec;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};

pub trait Sign<PrivateKey, Ring> {
    fn sign<
        Hash: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: PrivateKey,
        ring: Ring,
        message: &Vec<u8>,
    ) -> Self;
}

pub trait Verify {
    fn verify<Hash: Digest<OutputSize = U64> + Clone + Default>(
        signature: Self,
        message: &Vec<u8>,
    ) -> bool;
}

pub trait Link {
    fn link(signature_1: Self, signature_2: Self) -> bool;
}
