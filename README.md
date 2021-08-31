# IBE
Identity Based Encryption schemes on the [BLS12-381 pairing-friendly elliptic curve](https://github.com/zkcrypto/bls12_381) in Rust.
This crate contains both public-key encryption schemes (PKEs, see `src/pke`) and key encapsulation mechanisms (KEMs, see `src/kem`). References to papers appear in the respective source files.

Implements the following schemes (in chronological order):
* Waters (PKE)
* Waters-Naccache (PKE)
* Kiltz-Vahlis IBE1 (CCA2 KEM)
* Boyen-Waters (CPA KEM)
* Chen-Gay-Wee (CPA PKE, CPA/CCA2 KEM)

## Technical notes
* **This implementation has not (yet) been reviewed or audited. Use at your own risk.**
* Uses [SHA3-512](https://crates.io/crates/tiny-keccak) for hashing to identities, hashing to secrets and as symmetric primitives for the Fujisaki-Okamoto transform.
* Compiles succesfully on Rust Stable.
* Does not use the Rust standard library (no-std).
* The structure of the byte serialisation of the various datastructures is not guaranteed to remain constant between releases of this library.
* All operations in this library are implemented to run in constant time.
* The binary in sourced by the file in `src/bin/sizes.rs` produces a binary that prints various sizes of different schemes.

## TODO's
* The underlying libraries might benefit from running on Rust nightly, which prevents compiler optimizations that could jeopardize constant time operations, but enabling this will require using `subtle/nightly`.
* The performance of this library is heavily dependant on the arithmatic of the underlying curve, BLS12-381. Any new optimizations to the original library could significantly increase performance of the schemes in this crate. It should therefore be considered to merge these optimizations into this crate as well.
