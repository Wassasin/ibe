use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};

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
    let g1 = rand_g1(rng);
    let g2 = rand_g2(rng);
    bls12_381::pairing(&G1Affine::from(g1), &G2Affine::from(g2))
}
