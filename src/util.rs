use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use byteorder::{ByteOrder, LittleEndian};

// use pairing::bls12_381::{Fq, Fq12, Fq2, Fq6};

// pub(crate) trait Write {
//     fn write(&mut self, bytes: &[u8]);
// }

// pub(crate) struct Sha3Write(tiny_keccak::Keccak);

// impl Sha3Write {
//     pub fn new() -> Self {
//         Sha3Write(tiny_keccak::Keccak::new_sha3_256())
//     }

//     pub fn finalize(self) -> [u8; 32] {
//         let mut buf = [0u8; 32];
//         self.0.finalize(&mut buf);
//         buf
//     }
// }

// impl Write for Sha3Write {
//     fn write(&mut self, bytes: &[u8]) {
//         self.0.update(bytes);
//     }
// }

// pub(crate) trait Marshallable {
//     fn marshal(&self, w: &mut Write);
// }

// impl Marshallable for Fq {
//     fn marshal(&self, w: &mut Write) {
//         use pairing::PrimeField;

//         let buf = self.into_repr().0;

//         for x in buf.iter() {
//             w.write(&x.to_be_bytes());
//         }
//     }
// }

// impl Marshallable for Fq2 {
//     fn marshal(&self, w: &mut Write) {
//         self.c0.marshal(w);
//         self.c1.marshal(w);
//     }
// }

// impl Marshallable for Fq6 {
//     fn marshal(&self, w: &mut Write) {
//         self.c0.marshal(w);
//         self.c1.marshal(w);
//         self.c2.marshal(w);
//     }
// }

// impl Marshallable for Fq12 {
//     fn marshal(&self, w: &mut Write) {
//         self.c0.marshal(w);
//         self.c1.marshal(w);
//     }
// }

pub fn le_bytes_to_u64_slice(bytes: &[u8; 32]) -> [u64; 4] {
    [
        LittleEndian::read_u64(&bytes[0..8]),
        LittleEndian::read_u64(&bytes[8..16]),
        LittleEndian::read_u64(&bytes[16..24]),
        LittleEndian::read_u64(&bytes[24..32]),
    ]
}

#[allow(dead_code)]
pub fn le_u64_slice_to_bytes(slice: &[u64; 4]) -> [u8; 32] {
    let mut res = [0; 32];
    LittleEndian::write_u64(&mut res[0..8], slice[0]);
    LittleEndian::write_u64(&mut res[8..16], slice[1]);
    LittleEndian::write_u64(&mut res[16..24], slice[2]);
    LittleEndian::write_u64(&mut res[24..32], slice[3]);
    res
}

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

pub fn pow_scalar(lhs: &Scalar, rhs: &Scalar) -> Scalar {
    let e = le_bytes_to_u64_slice(&rhs.to_bytes());
    lhs.pow(&e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_bytes_u64_slice_reflective() {
        let borig = [0x1234567890123456, 1000001, 1000002, 1000003];
        let aorig = [
            0x56, 0x34, 0x12, 0x90, 0x78, 0x56, 0x34, 0x12, 65, 66, 15, 0, 0, 0, 0, 0, 66, 66, 15,
            0, 0, 0, 0, 0, 67, 66, 15, 0, 0, 0, 0, 0,
        ];
        let a = le_u64_slice_to_bytes(&borig);
        let b = le_bytes_to_u64_slice(&a);

        assert_eq!(aorig, a);
        assert_eq!(borig, b);
    }

    #[test]
    pub fn pow_scalar_one() {
        let res = pow_scalar(&Scalar::one(), &Scalar::one());

        assert_eq!(Scalar::one(), res);
    }
}
