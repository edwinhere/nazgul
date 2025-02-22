//! # Nazgul
//! A library that implements [Ring Signatures](https://en.wikipedia.org/wiki/Ring_signature). The following schemes have been implemented based on [Chapter 3 of Zero to Monero 2.0 (Z2M2)](https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf):
//!
//!  - Spontaneous Anonymous Group (SAG) signatures
//!  - Back's Linkable Spontaneous Anonymous Group (bLSAG) signatures
//!  - Multilayer Linkable Spontaneous Anonymous Group (MLSAG) signatures
//!  - Concise Linkable Spontaneous Anonymous Group (CLSAG) signatures
//!
//! ~~The following scheme has also been implemented from outside [Z2M2](https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf):~~
//!
//!  - ~~[DLSAG: Non-Interactive Refund Transactions For Interoperable Payment Channels in Monero](https://eprint.iacr.org/2019/595.pdf)~~
//!
//! Note: The MDLSAG (Multilayer Dual Linkable Spontaneous Anonymous Group) and DLSAG signature scheme was removed as its implementation did not correctly match the specifications in the [cited paper](https://eprint.iacr.org/2019/595.pdf).
//!
//! > All blockquotes (except this one) in this documentation are from [Z2M2](https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf)
//!
//! This library is designed to work with any 512-bit (64 byte output) hashing function. It uses the
//! [Ristretto elliptic curve](https://doc.dalek.rs/curve25519_dalek/ristretto/) for ease of use and better security.
//!
//! This library is `#![no_std]` by default so it is possible to compile this library for embedded devices and WebAssembly but we haven't tried.

#![no_std]

#[cfg(all(feature = "no_std", not(feature = "std")))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

extern crate curve25519_dalek;
extern crate digest;
extern crate rand_core;

pub mod blsag;
pub mod clsag;
pub mod mlsag;
pub(crate) mod prelude;
pub mod sag;
pub mod traits;
