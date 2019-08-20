# Waters
Identity Based Encryption Waters-Naccache scheme on the [BLS12-381 pairing-friendly elliptic curve](https://github.com/zkcrypto/bls12_381) in Rust.

## Sources
* Inspired by: [CHARM implementation](https://github.com/JHUISI/charm/blob/dev/charm/schemes/ibenc/ibenc_waters05.py)
* From: "[Secure and Practical Identity-Based Encryption](http://eprint.iacr.org/2005/369.pdf)"
* Published in: IET Information Security, 2007

## Technical notes
* **This implementation has not (yet) been reviewed or audited. Use at your own risk.**
* Uses [SHA3-512](https://crates.io/crates/tiny-keccak) for hashing to identities.
* Compiles succesfully on Rust Stable.
* Does not use the Rust standard library (no-std).
* The structure of the byte serialisation of the various datastructures is not guaranteed to remain constant between releases of this library.
* All operations in this library are implemented to run in constant time.

## TODO's
* Serialisation of `CipherText` might benefit from using a compressed format for `Gt`, as currently it serializes to a 576 bytes, which is relatively big.
* The underlying libraries might benefit from running on Rust nightly, which prevents compiler optimizations that could jeopardize constant time operations, but enabling this will require using `subtle/nightly`.