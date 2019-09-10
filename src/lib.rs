//! Identity Based Encryption schemes on the [BLS12-381 pairing-friendly elliptic curve](https://github.com/zkcrypto/bls12_381).
//!
//! Implements the following schemes:
//! * Waters
//! * Waters-Naccache
//! * Kiltz-Vahlis IBE1

#![no_std]

mod util;

pub mod kiltz_vahlis_one;
pub mod waters;
pub mod waters_naccache;
