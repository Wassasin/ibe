//! Fully-secure Identity Based Encryption by Chen, Gay and Wee.
//! * From: "[Improved Dual System ABE in Prime-Order Groups via Predicate Encodings](https://link.springer.com/chapter/10.1007/978-3-540-79263-5_14)"
//!
//! This file contains the passively (IND-CPA) secure KEM.

use crate::util::*;
use arrayref::{array_refs, mut_array_refs};
use core::convert::TryInto;
use irmaseal_curve::{
    multi_miller_loop, pairing, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
    Scalar,
};
use rand::Rng;
use subtle::CtOption;

// Max identity buf size
const K: usize = 256;
const N: usize = 2 * K;
const N_BYTE_LEN: usize = N / 8;

// Sizes of elements in particular groups (compressed)
const GT_BYTES: usize = 288;
const G1_BYTES: usize = 48;
const G2_BYTES: usize = 96;
const SCALAR_BYTES: usize = 32;

// Derived sizes
const PK_BYTES: usize = 6 * G1_BYTES + GT_BYTES;
const SK_BYTES: usize = 12 * SCALAR_BYTES;
const USK_BYTES: usize = 4 * G2_BYTES;
const CT_BYTES: usize = 4 * G1_BYTES;

/// Public key parameters generated by the PKG used to encrypt messages.
/// Also known as MPK.
#[derive(Clone, Copy, PartialEq)]
pub struct PublicKey {
    a_1: [G1Affine; 2],
    w0ta_1: [G1Affine; 2],
    w1ta_1: [G1Affine; 2],
    kta_t: Gt,
}

/// Secret key parameter generated by the PKG used to extract user secret keys.
/// Also known as MSK.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SecretKey {
    b: [Scalar; 2],
    k: [Scalar; 2],
    w0: [[Scalar; 2]; 2],
    w1: [[Scalar; 2]; 2],
}

/// User secret key. Can be used to decrypt the corresponding ciphertext.
/// Also known as USK_{id}.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct UserSecretKey {
    d0: [G2Affine; 2],
    d1: [G2Affine; 2],
}

/// Encrypted message. Can only be decrypted with a corresponding user secret key.
/// Also known as CT_{id}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CipherText {
    c0: [G1Affine; 2],
    c1: [G1Affine; 2],
}

/// Hashed byte representation of an identity.
pub struct Identity([u8; N_BYTE_LEN]);

/// A shared secret in the target group.
///
/// You can use the byte representation to derive, for example, an AES key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SharedSecret(Gt);

/// Generate a keypair used by the Private Key Generator (PKG).
pub fn setup<R: Rng>(rng: &mut R) -> (PublicKey, SecretKey) {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let a = [rand_scalar(rng), rand_scalar(rng)];
    let b = [rand_scalar(rng), rand_scalar(rng)];

    let w0 = [
        [rand_scalar(rng), rand_scalar(rng)],
        [rand_scalar(rng), rand_scalar(rng)],
    ];

    let w1 = [
        [rand_scalar(rng), rand_scalar(rng)],
        [rand_scalar(rng), rand_scalar(rng)],
    ];

    let k = [rand_scalar(rng), rand_scalar(rng)];

    let w0ta = [
        w0[0][0] * a[0] + w0[1][0] * a[1],
        w0[0][1] * a[0] + w0[1][1] * a[1],
    ];
    let w1ta = [
        w1[0][0] * a[0] + w1[1][0] * a[1],
        w1[0][1] * a[0] + w1[1][1] * a[1],
    ];

    let batch = [
        g1 * a[0],
        g1 * a[1],
        g1 * w0ta[0],
        g1 * w0ta[1],
        g1 * w1ta[0],
        g1 * w1ta[1],
    ];

    let mut out = [G1Affine::default(); 6];
    G1Projective::batch_normalize(&batch, &mut out);
    let kta_t = pairing(&g1, &g2) * (k[0] * a[0] + k[1] * a[1]);

    (
        PublicKey {
            a_1: [out[0], out[1]],
            w0ta_1: [out[2], out[3]],
            w1ta_1: [out[4], out[5]],
            kta_t,
        },
        SecretKey { b, k, w0, w1 },
    )
}

/// Extract a user secret key for a given identity.
pub fn extract_usk<R: Rng>(sk: &SecretKey, v: &Identity, rng: &mut R) -> UserSecretKey {
    let g2 = G2Affine::generator();
    let r = rand_scalar(rng);

    let br = [sk.b[0] * r, sk.b[1] * r];

    // X = W0 + id W1
    let id = v.to_scalar();
    let x = [
        [
            id * sk.w1[0][0] + sk.w0[0][0],
            id * sk.w1[0][1] + sk.w0[0][1],
        ],
        [
            id * sk.w1[1][0] + sk.w0[1][0],
            id * sk.w1[1][1] + sk.w0[1][1],
        ],
    ];

    let xbrplusk = [
        x[0][0] * br[0] + x[0][1] * br[1] + sk.k[0],
        x[1][0] * br[0] + x[1][1] * br[1] + sk.k[1],
    ];

    let batch = [g2 * br[0], g2 * br[1], g2 * xbrplusk[0], g2 * xbrplusk[1]];
    let mut out = [G2Affine::default(); 4];
    G2Projective::batch_normalize(&batch, &mut out);

    UserSecretKey {
        d0: [out[0], out[1]],
        d1: [out[2], out[3]],
    }
}

/// Generate a SharedSecret and corresponding Ciphertext for that key.
pub fn encaps<R: Rng>(pk: &PublicKey, v: &Identity, rng: &mut R) -> (CipherText, SharedSecret) {
    let s = rand_scalar(rng);
    let id = v.to_scalar();

    let batch = [
        pk.a_1[0] * s,
        pk.a_1[1] * s,
        (pk.w0ta_1[0] * s) + (pk.w1ta_1[0] * (s * id)),
        (pk.w0ta_1[1] * s) + (pk.w1ta_1[1] * (s * id)),
    ];

    let mut out = [G1Affine::default(); 4];
    G1Projective::batch_normalize(&batch, &mut out);

    let cprime = pk.kta_t * s;

    (
        CipherText {
            c0: [out[0], out[1]],
            c1: [out[2], out[3]],
        },
        SharedSecret(cprime),
    )
}

/// Derive the same SharedSecret from the CipherText using a UserSecretKey.
pub fn decaps(usk: &UserSecretKey, ct: &CipherText) -> SharedSecret {
    let m = multi_miller_loop(&[
        (&ct.c0[0], &G2Prepared::from(usk.d1[0])),
        (&ct.c0[1], &G2Prepared::from(usk.d1[1])),
        (&-ct.c1[0], &G2Prepared::from(usk.d0[0])),
        (&-ct.c1[1], &G2Prepared::from(usk.d0[1])),
    ])
    .final_exponentiation();

    SharedSecret(m)
}

impl Identity {
    /// Hash a byte slice to a set of Identity parameters, which acts as a user public key.
    /// Uses sha3-512 internally.
    pub fn derive(b: &[u8]) -> Identity {
        Identity(sha3_512(b))
    }

    /// Hash a string slice to a set of Identity parameters.
    /// Directly converts characters to UTF-8 byte representation.
    pub fn derive_str(s: &str) -> Identity {
        Self::derive(s.as_bytes())
    }

    fn to_scalar(&self) -> Scalar {
        Scalar::from_bytes_wide(&self.0)
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

impl SharedSecret {
    pub fn to_bytes(&self) -> [u8; GT_BYTES] {
        self.0.to_compressed()
    }

    pub fn from_bytes(bytes: &[u8; GT_BYTES]) -> CtOption<Self> {
        Gt::from_compressed(bytes).map(Self)
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; PK_BYTES] {
        let mut res = [0u8; PK_BYTES];

        for i in 0..2 {
            let x = i * G1_BYTES;
            let y = x + 2 * G1_BYTES;
            let z = y + 2 * G1_BYTES;
            res[x..x + G1_BYTES].copy_from_slice(&self.a_1[i].to_compressed());
            res[y..y + G1_BYTES].copy_from_slice(&self.w0ta_1[i].to_compressed());
            res[z..z + G1_BYTES].copy_from_slice(&self.w1ta_1[i].to_compressed());
        }

        res[6 * G1_BYTES..].copy_from_slice(&self.kta_t.to_compressed());

        res
    }

    pub fn from_bytes(bytes: &[u8; PK_BYTES]) -> CtOption<Self> {
        // from_compressed_unchecked doesn't check whether the element has
        // a cofactor. To mount an attack using a cofactor an attacker
        // must be able to manipulate the public parameters. But then the
        // attacker can simply use parameters they generated themselves.
        // Thus checking for a cofactor is superfluous.
        let a10 = G1Affine::from_compressed_unchecked(bytes[0..48].try_into().unwrap());
        let a11 = G1Affine::from_compressed_unchecked(bytes[48..96].try_into().unwrap());
        let w0ta10 = G1Affine::from_compressed_unchecked(bytes[96..144].try_into().unwrap());
        let w0ta11 = G1Affine::from_compressed_unchecked(bytes[144..192].try_into().unwrap());
        let w1ta10 = G1Affine::from_compressed_unchecked(bytes[192..240].try_into().unwrap());
        let w1ta11 = G1Affine::from_compressed_unchecked(bytes[240..288].try_into().unwrap());
        let kta_t = Gt::from_compressed_unchecked(bytes[288..576].try_into().unwrap());

        a10.and_then(|a10| {
            a11.and_then(|a11| {
                w0ta10.and_then(|w0ta10| {
                    w0ta11.and_then(|w0ta11| {
                        w1ta10.and_then(|w1ta10| {
                            w1ta11.and_then(|w1ta11| {
                                kta_t.map(|kta_t| PublicKey {
                                    a_1: [a10, a11],
                                    w0ta_1: [w0ta10, w0ta11],
                                    w1ta_1: [w1ta10, w1ta11],
                                    kta_t,
                                })
                            })
                        })
                    })
                })
            })
        })
    }
}

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; SK_BYTES] {
        let mut res = [0u8; SK_BYTES];
        let (mut x, mut y);

        for i in 0..2 {
            x = i * SCALAR_BYTES;
            y = x + 2 * SCALAR_BYTES;
            res[x..x + SCALAR_BYTES].copy_from_slice(&self.b[i].to_bytes());
            res[y..y + SCALAR_BYTES].copy_from_slice(&self.k[i].to_bytes());

            for j in 0..2 {
                x = (2 * i + j + 4) * SCALAR_BYTES;
                y = x + 4 * SCALAR_BYTES;
                res[x..x + SCALAR_BYTES].copy_from_slice(&self.w0[i][j].to_bytes());
                res[y..y + SCALAR_BYTES].copy_from_slice(&self.w1[i][j].to_bytes());
            }
        }

        res
    }

    pub fn from_bytes(bytes: &[u8; SK_BYTES]) -> CtOption<Self> {
        let b0 = Scalar::from_bytes(&bytes[0..32].try_into().unwrap());
        let b1 = Scalar::from_bytes(&bytes[32..64].try_into().unwrap());
        let k0 = Scalar::from_bytes(&bytes[64..96].try_into().unwrap());
        let k1 = Scalar::from_bytes(&bytes[96..128].try_into().unwrap());

        let w000 = Scalar::from_bytes(&bytes[128..160].try_into().unwrap());
        let w001 = Scalar::from_bytes(&bytes[160..192].try_into().unwrap());
        let w010 = Scalar::from_bytes(&bytes[192..224].try_into().unwrap());
        let w011 = Scalar::from_bytes(&bytes[224..256].try_into().unwrap());

        let w100 = Scalar::from_bytes(&bytes[256..288].try_into().unwrap());
        let w101 = Scalar::from_bytes(&bytes[288..320].try_into().unwrap());
        let w110 = Scalar::from_bytes(&bytes[320..352].try_into().unwrap());
        let w111 = Scalar::from_bytes(&bytes[352..384].try_into().unwrap());

        b0.and_then(|b0| {
            b1.and_then(|b1| {
                k0.and_then(|k0| {
                    k1.and_then(|k1| {
                        w000.and_then(|w000| {
                            w001.and_then(|w001| {
                                w010.and_then(|w010| {
                                    w011.and_then(|w011| {
                                        w100.and_then(|w100| {
                                            w101.and_then(|w101| {
                                                w110.and_then(|w110| {
                                                    w111.map(|w111| SecretKey {
                                                        b: [b0, b1],
                                                        k: [k0, k1],
                                                        w0: [[w000, w001], [w010, w011]],
                                                        w1: [[w100, w101], [w110, w111]],
                                                    })
                                                })
                                            })
                                        })
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    }
}

impl UserSecretKey {
    pub fn to_bytes(&self) -> [u8; USK_BYTES] {
        let mut res = [0u8; USK_BYTES];
        let (d00, d01, d10, d11) =
            mut_array_refs![&mut res, G2_BYTES, G2_BYTES, G2_BYTES, G2_BYTES];

        *d00 = self.d0[0].to_compressed();
        *d01 = self.d0[1].to_compressed();
        *d10 = self.d1[0].to_compressed();
        *d11 = self.d1[1].to_compressed();

        res
    }
    pub fn from_bytes(bytes: &[u8; USK_BYTES]) -> CtOption<Self> {
        let (d00, d01, d10, d11) = array_refs![bytes, G2_BYTES, G2_BYTES, G2_BYTES, G2_BYTES];

        let d00 = G2Affine::from_compressed(d00);
        let d01 = G2Affine::from_compressed(d01);
        let d10 = G2Affine::from_compressed(d10);
        let d11 = G2Affine::from_compressed(d11);

        d00.and_then(|d00| {
            d01.and_then(|d01| {
                d10.and_then(|d10| {
                    d11.map(|d11| UserSecretKey {
                        d0: [d00, d01],
                        d1: [d10, d11],
                    })
                })
            })
        })
    }
}

impl CipherText {
    pub fn to_bytes(&self) -> [u8; CT_BYTES] {
        let mut res = [0u8; CT_BYTES];
        let (c00, c01, c10, c11) =
            mut_array_refs![&mut res, G1_BYTES, G1_BYTES, G1_BYTES, G1_BYTES];

        *c00 = self.c0[0].to_compressed();
        *c01 = self.c0[1].to_compressed();
        *c10 = self.c1[0].to_compressed();
        *c11 = self.c1[1].to_compressed();

        res
    }

    pub fn from_bytes(bytes: &[u8; CT_BYTES]) -> CtOption<Self> {
        let (c00, c01, c10, c11) = array_refs![bytes, G1_BYTES, G1_BYTES, G1_BYTES, G1_BYTES];

        let c00 = G1Affine::from_compressed(c00);
        let c01 = G1Affine::from_compressed(c01);
        let c10 = G1Affine::from_compressed(c10);
        let c11 = G1Affine::from_compressed(c11);

        c00.and_then(|c00| {
            c01.and_then(|c01| {
                c10.and_then(|c10| {
                    c11.map(|c11| CipherText {
                        c0: [c00, c01],
                        c1: [c10, c11],
                    })
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &'static [u8] = b"email:w.geraedts@sarif.nl";

    #[allow(dead_code)]
    struct DefaultSubResults {
        pk: PublicKey,
        sk: SecretKey,
        usk: UserSecretKey,
        c: CipherText,
        ss: SharedSecret,
    }

    fn perform_default() -> DefaultSubResults {
        let mut rng = rand::thread_rng();

        let kid = Identity::derive(ID);

        let (pk, sk) = setup(&mut rng);
        let usk = extract_usk(&sk, &kid, &mut rng);

        let (c, ss) = encaps(&pk, &kid, &mut rng);

        DefaultSubResults { pk, sk, usk, c, ss }
    }

    #[test]
    fn eq_encaps_decaps() {
        let results = perform_default();
        let ss2 = decaps(&results.usk, &results.c);

        assert_eq!(results.ss, ss2);
    }
    #[test]
    fn eq_serialize_deserialize() {
        let result = perform_default();

        assert_eq!(
            result.ss,
            SharedSecret::from_bytes(&result.ss.to_bytes()).unwrap()
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
