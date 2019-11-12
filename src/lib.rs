//! Identity Based Encryption schemes on the [BLS12-381 pairing-friendly elliptic curve](https://github.com/zkcrypto/bls12_381).
//!
//! Implements the following schemes:
//! * Waters
//! * Waters-Naccache
//! * Kiltz-Vahlis IBE1

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

// A hard-copy of bls12_381, because original maintainers are inactive at the moment.
mod bls12_381;
pub(crate) use crate::bls12_381::*;

mod util;

pub mod kiltz_vahlis_one;
pub mod waters;
pub mod waters_naccache;
