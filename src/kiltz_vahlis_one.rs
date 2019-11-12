//! Identity Based Encryption Kiltz-Vahlis IBE1 scheme on the [BLS12-381 pairing-friendly elliptic curve](https://github.com/zkcrypto/bls12_381).
//!  * From: "[CCA2 Secure IBE: Standard Model Efficiency through Authenticated Symmetric Encryption](https://link.springer.com/chapter/10.1007/978-3-540-79263-5_14)"
//!  * Published in: CT-RSA, 2008
//!
//! Uses [SHA3-512](https://crates.io/crates/tiny-keccak) for hashing to identities.
//!
//! The structure of the byte serialisation of the various datastructures is not guaranteed
//! to remain constant between releases of this library.
//! All operations in this library are implemented to run in constant time.

use crate::bls12_381::{G1Affine, G1Projective, G2Affine, Gt, Scalar};
use crate::util::*;
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use rand::Rng;
use subtle::{Choice, ConditionallySelectable, CtOption};

const K: usize = 256;
const N: usize = 2 * K;
const N_BYTE_LEN: usize = N / 8;

const HASH_PARAMETER_SIZE: usize = N * 48;

const PUBLICKEYSIZE: usize = 96 + 48 + HASH_PARAMETER_SIZE + 48 + 288;

struct HashParameters([G1Affine; N]);

/// Public key parameters generated by the PKG used to encrypt messages.
#[derive(Clone, Copy, PartialEq)]
pub struct PublicKey {
    g: G2Affine,
    hzero: G1Affine,
    h: HashParameters,
    u: G1Affine,
    z: Gt,
}

/// Secret key parameter generated by the PKG used to extract user secret keys.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SecretKey {
    alpha: G1Affine,
}

/// Points on the paired curves that form the user secret key.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct UserSecretKey {
    d1: G1Affine,
    d2: G2Affine,
    d3: G1Affine,
}

/// Byte representation of an identity.
///
/// Can be hashed to the curve together with some parameters from the Public Key.
pub struct Identity([u8; N_BYTE_LEN]);

/// Encrypted message. Can only be decrypted with an user secret key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CipherText {
    c1: G2Affine,
    c2: G1Affine,
}

/// A point on the paired curve that can be encrypted and decrypted.
///
/// You can use the byte representation to derive an AES key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SymmetricKey(Gt);

/// Generate a keypair used by the Private Key Generator (PKG).
pub fn setup<R: Rng>(rng: &mut R) -> (PublicKey, SecretKey) {
    let g: G2Affine = rand_g2(rng).into();

    let alpha: G1Affine = rand_g1(rng).into();
    let u: G1Affine = rand_g1(rng).into();
    let z = crate::bls12_381::pairing(&alpha, &g);

    let hzero = G1Affine::default();
    let mut h = HashParameters([G1Affine::default(); N]);
    for hi in h.0.iter_mut() {
        *hi = rand_g1(rng).into();
    }

    let pk = PublicKey { g, hzero, h, u, z };
    let sk = SecretKey { alpha };

    (pk, sk)
}

fn hash_to_curve(pk: &PublicKey, v: &Identity) -> G1Projective {
    let mut hcoll: G1Projective = pk.hzero.into();
    for (hi, vi) in pk.h.0.iter().zip(bits(&v.0)) {
        hcoll = G1Projective::conditional_select(&hcoll, &(hi + hcoll), vi);
    }
    hcoll
}

fn hash_g2_to_scalar(x: G2Affine) -> Scalar {
    let buf = tiny_keccak::sha3_512(&x.to_uncompressed());
    Scalar::from_bytes_wide(&buf)
}

/// Extract an user secret key for a given identity.
pub fn extract_usk<R: Rng>(
    pk: &PublicKey,
    sk: &SecretKey,
    v: &Identity,
    rng: &mut R,
) -> UserSecretKey {
    let s = rand_scalar(rng);

    let d1 = (sk.alpha + (hash_to_curve(pk, v) * s)).into();
    let d2 = (pk.g * (-s)).into();
    let d3 = (pk.u * s).into();

    UserSecretKey { d1, d2, d3 }
}

/// Generate a symmetric key and corresponding CipherText for that key.
pub fn encrypt<R: Rng>(pk: &PublicKey, v: &Identity, rng: &mut R) -> (CipherText, SymmetricKey) {
    let r = rand_scalar(rng);

    let c1 = (pk.g * r).into();
    let t = hash_g2_to_scalar(c1);
    let c2 = ((hash_to_curve(pk, v) + (pk.u * t)) * r).into();
    let k = pk.z * r;

    (CipherText { c1, c2 }, SymmetricKey(k))
}

/// Decrypt ciphertext to a SymmetricKey using a user secret key.
pub fn decrypt(usk: &UserSecretKey, c: &CipherText) -> SymmetricKey {
    let t = hash_g2_to_scalar(c.c1);
    let k1 = crate::bls12_381::pairing(&(usk.d1 + (usk.d3 * t)).into(), &c.c1);
    let k2 = crate::bls12_381::pairing(&c.c2, &usk.d2);

    let k = k1 + k2;

    SymmetricKey(k)
}

impl Identity {
    /// Hash a byte slice to a set of Identity parameters, which acts as a user public key.
    /// Uses sha3-512 internally.
    pub fn derive(b: &[u8]) -> Identity {
        Identity(tiny_keccak::sha3_512(b))
    }

    /// Hash a string slice to a set of Identity parameters.
    /// Directly converts characters to UTF-8 byte representation.
    pub fn derive_str(s: &str) -> Identity {
        Self::derive(s.as_bytes())
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        let mut res = [u8::default(); N_BYTE_LEN];
        for (src, dst) in self.0.iter().zip(res.as_mut().iter_mut()) {
            *dst = *src;
        }
        Identity(res)
    }
}

impl Copy for Identity {}

impl SymmetricKey {
    pub fn to_bytes(&self) -> [u8; 288] {
        self.0.to_compressed()
    }

    pub fn from_bytes(bytes: &[u8; 288]) -> CtOption<Self> {
        Gt::from_compressed(bytes).map(Self)
    }
}

impl HashParameters {
    pub fn to_bytes(&self) -> [u8; HASH_PARAMETER_SIZE] {
        let mut res = [0u8; HASH_PARAMETER_SIZE];
        for i in 0..N {
            *array_mut_ref![&mut res, i * 48, 48] = self.0[i].to_compressed();
        }
        res
    }

    pub fn from_bytes(bytes: &[u8; HASH_PARAMETER_SIZE]) -> CtOption<Self> {
        let mut res = [G1Affine::default(); N];
        let mut is_some = Choice::from(1u8);
        for i in 0..N {
            is_some &= G1Affine::from_compressed(array_ref![bytes, i * 48, 48])
                .map(|s| {
                    res[i] = s;
                })
                .is_some();
        }
        CtOption::new(HashParameters(res), is_some)
    }
}

impl ConditionallySelectable for HashParameters {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut res = [G1Affine::default(); N];
        for (i, (ai, bi)) in a.0.iter().zip(b.0.iter()).enumerate() {
            res[i] = G1Affine::conditional_select(&ai, &bi, choice);
        }
        HashParameters(res)
    }
}

impl PartialEq for HashParameters {
    fn eq(&self, rhs: &HashParameters) -> bool {
        self.0.iter().zip(rhs.0.iter()).all(|(x, y)| x.eq(y))
    }
}

impl Clone for HashParameters {
    fn clone(&self) -> Self {
        let mut res = [G1Affine::default(); N];
        for (src, dst) in self.0.iter().zip(res.as_mut().iter_mut()) {
            *dst = *src;
        }
        Self(res)
    }
}

impl Copy for HashParameters {}

impl Default for HashParameters {
    fn default() -> Self {
        HashParameters([G1Affine::default(); N])
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; PUBLICKEYSIZE] {
        let mut res = [0u8; PUBLICKEYSIZE];

        let (g, hzero, h, u, z) = mut_array_refs![&mut res, 96, 48, HASH_PARAMETER_SIZE, 48, 288];
        *g = self.g.to_compressed();
        *hzero = self.hzero.to_compressed();
        *h = self.h.to_bytes();
        *u = self.u.to_compressed();
        *z = self.z.to_compressed();
        res
    }

    pub fn from_bytes(bytes: &[u8; PUBLICKEYSIZE]) -> CtOption<Self> {
        let (g, hzero, h, u, z) = array_refs![&bytes, 96, 48, HASH_PARAMETER_SIZE, 48, 288];

        let g = G2Affine::from_compressed(g);
        let hzero = G1Affine::from_compressed(hzero);
        let h = HashParameters::from_bytes(h);
        let u = G1Affine::from_compressed(u);
        let z = Gt::from_compressed(z);

        g.and_then(|g| {
            hzero.and_then(|hzero| {
                h.and_then(|h| u.and_then(|u| z.map(|z| PublicKey { g, hzero, h, u, z })))
            })
        })
    }
}

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; 48] {
        self.alpha.to_compressed()
    }

    pub fn from_bytes(bytes: &[u8; 48]) -> CtOption<Self> {
        G1Affine::from_compressed(bytes).map(|alpha| SecretKey { alpha })
    }
}

impl UserSecretKey {
    pub fn to_bytes(&self) -> [u8; 192] {
        let mut res = [0u8; 192];
        let (d1, d2, d3) = mut_array_refs![&mut res, 48, 96, 48];
        *d1 = self.d1.to_compressed();
        *d2 = self.d2.to_compressed();
        *d3 = self.d3.to_compressed();
        res
    }

    pub fn from_bytes(bytes: &[u8; 192]) -> CtOption<Self> {
        let (d1, d2, d3) = array_refs![bytes, 48, 96, 48];

        let d1 = G1Affine::from_compressed(d1);
        let d2 = G2Affine::from_compressed(d2);
        let d3 = G1Affine::from_compressed(d3);

        d1.and_then(|d1| d2.and_then(|d2| d3.map(|d3| UserSecretKey { d1, d2, d3 })))
    }
}

impl CipherText {
    pub fn to_bytes(&self) -> [u8; 144] {
        let mut res = [0u8; 144];
        let (c1, c2) = mut_array_refs![&mut res, 96, 48];
        *c1 = self.c1.to_compressed();
        *c2 = self.c2.to_compressed();
        res
    }

    pub fn from_bytes(bytes: &[u8; 144]) -> CtOption<Self> {
        let (c1, c2) = array_refs![bytes, 96, 48];

        let c1 = G2Affine::from_compressed(c1);
        let c2 = G1Affine::from_compressed(c2);

        c1.and_then(|c1| c2.map(|c2| CipherText { c1, c2 }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &'static str = "email:w.geraedts@sarif.nl";

    #[allow(dead_code)]
    struct DefaultSubResults {
        kid: Identity,
        pk: PublicKey,
        sk: SecretKey,
        usk: UserSecretKey,
        c: CipherText,
        k: SymmetricKey,
    }

    fn perform_default() -> DefaultSubResults {
        let mut rng = rand::thread_rng();

        let id = ID.as_bytes();
        let kid = Identity::derive(id);

        let (pk, sk) = setup(&mut rng);
        let usk = extract_usk(&pk, &sk, &kid, &mut rng);

        let (c, k) = encrypt(&pk, &kid, &mut rng);

        DefaultSubResults {
            kid,
            pk,
            sk,
            usk,
            c,
            k,
        }
    }

    #[test]
    fn eq_encrypt_decrypt() {
        let results = perform_default();
        let k2 = decrypt(&results.usk, &results.c);

        assert_eq!(results.k, k2);
    }

    #[test]
    fn eq_serialize_deserialize() {
        let result = perform_default();

        assert_eq!(
            result.k,
            SymmetricKey::from_bytes(&result.k.to_bytes()).unwrap()
        );
        assert!(result.pk == PublicKey::from_bytes(&result.pk.to_bytes()).unwrap());
        assert_eq!(
            result.sk,
            SecretKey::from_bytes(&result.sk.to_bytes()).unwrap()
        );
        assert_eq!(
            result.usk,
            UserSecretKey::from_bytes(&result.usk.to_bytes()).unwrap()
        );
        assert_eq!(
            result.c,
            CipherText::from_bytes(&result.c.to_bytes()).unwrap()
        );
    }
}