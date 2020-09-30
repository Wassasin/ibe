use irmaseal_curve::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};

pub fn rand_scalar<R: ::rand::Rng>(rng: &mut R) -> Scalar {
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);

    Scalar::from_bytes_wide(&buf)
}

pub fn rand_g1<R: ::rand::Rng>(rng: &mut R) -> G1Projective {
    use core::ops::Mul;
    let g = G1Projective::generator();
    let x = rand_scalar(rng);
    g.mul(x)
}

pub fn rand_g2<R: ::rand::Rng>(rng: &mut R) -> G2Projective {
    use core::ops::Mul;
    let g = G2Projective::generator();
    let x = rand_scalar(rng);
    g.mul(x)
}

pub fn rand_gt<R: ::rand::Rng>(rng: &mut R) -> Gt {
    let generator = irmaseal_curve::pairing(&G1Affine::generator(), &G2Affine::generator());

    let r = rand_scalar(rng);
    generator * r
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
