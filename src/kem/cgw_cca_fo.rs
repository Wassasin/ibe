//! Fully-secure Identity Based Encryption by Chen, Gay and Wee.
//! * From: "[Improved Dual System ABE in Prime-Order Groups via Predicate Encodings](https://link.springer.com/chapter/10.1007/978-3-540-79263-5_14)"
//!
//! CCA security due to a general approach by Fujisaki and Okamoto.
//! * From: "[A Modular Analysis of the Fujisaki-Okamoto Transformation](https://eprint.iacr.org/2017/604.pdf)"
//!
//! Symmetric primitives G and H instantiated using sha3_512 and sha3_256, respectively.
//! To output a bigger secret SHAKE256 can be used for example.
//!
//! A drawback of a Fujisaki-Okamoto transform is that we now need the public key to decapsulate :(

use crate::pke::cgw_cpa::{
    decrypt, encrypt, CipherText, Message, CT_BYTES, GT_BYTES, GT_UNCOMPRESSED_BYTES, N_BYTE_LEN,
    USK_BYTES,
};
use crate::util::*;
use arrayref::{array_refs, mut_array_refs};
use rand::Rng;
use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};

pub use crate::pke::cgw_cpa::{Identity, PublicKey, SecretKey};

const CCA_USK_BYTES: usize = USK_BYTES + GT_BYTES + N_BYTE_LEN;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SharedSecret([u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UserSecretKey {
    usk: crate::pke::cgw_cpa::UserSecretKey,
    s: Message,
    id: Identity,
}

impl UserSecretKey {
    pub fn to_bytes(&self) -> [u8; CCA_USK_BYTES] {
        let mut buf = [0u8; CCA_USK_BYTES];
        let (usk, s, id) = mut_array_refs![&mut buf, USK_BYTES, GT_BYTES, N_BYTE_LEN];

        *usk = self.usk.to_bytes();
        *s = self.s.to_compressed();
        id.copy_from_slice(&self.id.0);

        buf
    }

    pub fn from_bytes(bytes: &[u8; CCA_USK_BYTES]) -> CtOption<Self> {
        let (usk, s, id) = array_refs![&bytes, USK_BYTES, GT_BYTES, N_BYTE_LEN];

        let usk = crate::pke::cgw_cpa::UserSecretKey::from_bytes(usk);
        let s = Message::from_compressed(s);

        usk.and_then(|usk| {
            s.map(|s| UserSecretKey {
                usk,
                s,
                id: crate::pke::cgw_cpa::Identity(*id),
            })
        })
    }
}

pub fn setup<R: Rng>(rng: &mut R) -> (PublicKey, SecretKey) {
    crate::pke::cgw_cpa::setup(rng)
}

pub fn extract_usk<R: Rng>(sk: &SecretKey, id: &Identity, rng: &mut R) -> UserSecretKey {
    let usk = crate::pke::cgw_cpa::extract_usk(sk, id, rng);

    // include a random target group element to return in case of decapsulation failure.
    let s = Message::random(rng);

    UserSecretKey { usk, s, id: *id }
}

pub fn encaps<R: Rng>(pk: &PublicKey, v: &Identity, rng: &mut R) -> (CipherText, SharedSecret) {
    // Generate a random message in the target group
    let m = Message::random(rng);

    // encrypt() takes 64 bytes of randomness in this case
    // deterministically generate the randomness from the message using G = sha3_512
    let coins = sha3_512(&m.to_uncompressed());

    // encrypt the message using deterministic randomness
    let c = encrypt(pk, v, &m, &coins);

    // output the shared secret as H(m, c)
    let mut pre_k = [0u8; GT_UNCOMPRESSED_BYTES + CT_BYTES];
    pre_k[0..GT_UNCOMPRESSED_BYTES].copy_from_slice(&m.to_uncompressed());
    pre_k[GT_UNCOMPRESSED_BYTES..].copy_from_slice(&c.to_bytes());

    let k = sha3_256(&pre_k);

    (c, SharedSecret(k))
}

pub fn decaps(pk: &PublicKey, usk: &UserSecretKey, ct: &CipherText) -> SharedSecret {
    // Attempt to decrypt the message from the ciphertext
    let m = decrypt(&usk.usk, ct);

    // Regenerate the deterministic randomness
    let coins = sha3_512(&m.to_uncompressed());

    // Re-encrypt the message
    let ct2 = encrypt(pk, &usk.id, &m, &coins);

    // If the ciphertexts were equal, return H(m', c) otherwise return H(s, c), in constant time
    let m = Message::conditional_select(&m, &usk.s, ct.ct_eq(&ct2));

    let mut pre_k = [0u8; GT_UNCOMPRESSED_BYTES + CT_BYTES];
    pre_k[0..GT_UNCOMPRESSED_BYTES].copy_from_slice(&m.to_uncompressed());

    // TODO: can possibly improve performance by not compressing here
    pre_k[GT_UNCOMPRESSED_BYTES..].copy_from_slice(&ct.to_bytes());

    SharedSecret(sha3_256(&pre_k))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &'static [u8] = b"email:w.geraedts@sarif.nl";

    #[allow(dead_code)]
    struct DefaultSubResults {
        pk: PublicKey,
        id: Identity,
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

        DefaultSubResults {
            pk,
            id: kid,
            sk,
            usk,
            c,
            ss,
        }
    }

    #[test]
    fn eq_encaps_decaps() {
        let results = perform_default();
        let ss2 = decaps(&results.pk, &results.usk, &results.c);

        assert_eq!(results.ss, ss2);
    }

    #[test]
    fn eq_serialize_deserialize() {
        let result = perform_default();

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
