# IBE
Identity Based Encryption schemes on the [BLS12-381 pairing-friendly elliptic curve](https://github.com/zkcrypto/bls12_381) in Rust.

Implements the following schemes:
* Waters
* Waters-Naccache
* Kiltz-Vahlis IBE1

You should probably use the Kiltz-Vahlis IBE1 scheme, as it provides the best security properties.

## Technical notes
* **This implementation has not (yet) been reviewed or audited. Use at your own risk.**
* Uses [SHA3-512](https://crates.io/crates/tiny-keccak) for hashing to identities.
* Compiles succesfully on Rust Stable.
* Does not use the Rust standard library (no-std).
* The structure of the byte serialisation of the various datastructures is not guaranteed to remain constant between releases of this library.
* All operations in this library are implemented to run in constant time.

## TODO's
* The underlying libraries might benefit from running on Rust nightly, which prevents compiler optimizations that could jeopardize constant time operations, but enabling this will require using `subtle/nightly`.