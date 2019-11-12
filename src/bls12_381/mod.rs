//! # `bls12_381`
//!
//! This is a hard-copy of the bls12_318 crate that provides an implementation of the BLS12-381 pairing-friendly elliptic
//! curve construction.
//!
//! * **This implementation has not been reviewed or audited. Use at your own risk.**
//! * This implementation targets Rust `1.36` or later.
//! * This implementation does not require the Rust standard library.
//! * All operations are constant time unless explicitly noted.

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::many_single_char_names)]
// This lint is described at
// https://rust-lang.github.io/rust-clippy/master/index.html#suspicious_arithmetic_impl
// In our library, some of the arithmetic involving extension fields will necessarily
// involve various binary operators, and so this lint is triggered unnecessarily.
#![allow(clippy::suspicious_arithmetic_impl)]

#[cfg(feature = "pairings")]
extern crate alloc;

#[macro_use]
pub(crate) mod util;

pub(crate) mod scalar;

pub use scalar::Scalar;

pub(crate) mod fp;
pub(crate) mod fp2;
pub(crate) mod g1;
pub(crate) mod g2;

pub use g1::{G1Affine, G1Projective};
pub use g2::{G2Affine, G2Projective};

pub(crate) mod fp12;
pub(crate) mod fp6;

// The BLS parameter x for BLS12-381 is -0xd201000000010000
pub(crate) const BLS_X: u64 = 0xd201000000010000;
pub(crate) const BLS_X_IS_NEGATIVE: bool = true;

pub(crate) mod pairings;

pub use pairings::{pairing, Gt, MillerLoopResult};

// TODO: This should be upstreamed to subtle.
// See https://github.com/dalek-cryptography/subtle/pull/48
pub(crate) trait CtOptionExt<T> {
    /// Calls f() and either returns self if it contains a value,
    /// or returns the output of f() otherwise.
    fn or_else<F: FnOnce() -> subtle::CtOption<T>>(self, f: F) -> subtle::CtOption<T>;
}

impl<T: subtle::ConditionallySelectable> CtOptionExt<T> for subtle::CtOption<T> {
    fn or_else<F: FnOnce() -> subtle::CtOption<T>>(self, f: F) -> subtle::CtOption<T> {
        let is_none = self.is_none();
        let f = f();

        subtle::ConditionallySelectable::conditional_select(&self, &f, is_none)
    }
}
