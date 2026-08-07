//! Module for defining library-wide error types.

/// Represents the possible errors that can occur during signature operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SignatureError {
    /// Occurs when the signer's public key is not found within the provided ring.
    SignerNotFound,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignatureError::SignerNotFound => write!(f, "The signer's public key was not found in the ring"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignatureError {}
