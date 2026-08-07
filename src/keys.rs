use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};

/// A keypair containing a private key (`Scalar`) and its corresponding public key (`RistrettoPoint`).
///
/// This struct provides a type-safe way to manage cryptographic keys. The private key
/// is kept secret, while the public key can be shared.
#[derive(Clone, Debug)]
pub struct Keypair {
    private_key: Scalar,
    public_key: RistrettoPoint,
}

impl Keypair {
    /// Generates a new random keypair using a cryptographically secure random number generator.
    ///
    /// # Arguments
    ///
    /// *   `csprng`: A cryptographically secure random number generator.
    pub fn generate<R: RngCore + CryptoRng>(csprng: &mut R) -> Self {
        let private_key = Scalar::random(csprng);
        let public_key = &private_key * RISTRETTO_BASEPOINT_POINT;
        Self {
            private_key,
            public_key,
        }
    }

    /// Returns the private key.
    pub fn private_key(&self) -> &Scalar {
        &self.private_key
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &RistrettoPoint {
        &self.public_key
    }
}
