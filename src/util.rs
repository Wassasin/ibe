use group::{ff::Field, Group};
use irmaseal_curve::{G1Projective, G2Projective, Gt, Scalar};
use rand::RngCore;

#[inline]
pub fn rand_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    Scalar::random(rng)
}

#[inline]
pub fn rand_g1<R: RngCore>(rng: &mut R) -> G1Projective {
    G1Projective::random(rng)
}

#[inline]
pub fn rand_g2<R: RngCore>(rng: &mut R) -> G2Projective {
    G2Projective::random(rng)
}

#[inline]
pub fn rand_gt<R: RngCore>(rng: &mut R) -> Gt {
    Gt::random(rng)
}

pub fn bits<'a>(slice: &'a [u8]) -> impl Iterator<Item = subtle::Choice> + 'a {
    slice
        .iter()
        .rev()
        .zip((0..8).rev())
        .map(|(x, i)| subtle::Choice::from((*x >> i) & 1))
}

pub fn sha3_256(slice: &[u8]) -> [u8; 32] {
    use tiny_keccak::Hasher;

    let mut digest = tiny_keccak::Sha3::v256();
    digest.update(slice);

    let mut buf = [0u8; 32];
    digest.finalize(&mut buf);

    return buf;
}

pub fn sha3_512(slice: &[u8]) -> [u8; 64] {
    use tiny_keccak::Hasher;

    let mut digest = tiny_keccak::Sha3::v512();
    digest.update(slice);

    let mut buf = [0u8; 64];
    digest.finalize(&mut buf);

    return buf;
}
