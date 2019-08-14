use pairing::bls12_381::{Fq, Fq12, Fq2, Fq6};

pub(crate) trait Write {
    fn write(&mut self, bytes: &[u8]);
}

pub(crate) struct Sha3Write(tiny_keccak::Keccak);

impl Sha3Write {
    pub fn new() -> Self {
        Sha3Write(tiny_keccak::Keccak::new_sha3_256())
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        self.0.finalize(&mut buf);
        buf
    }
}

impl Write for Sha3Write {
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

pub(crate) trait Marshallable {
    fn marshal(&self, w: &mut Write);
}

impl Marshallable for Fq {
    fn marshal(&self, w: &mut Write) {
        use pairing::PrimeField;

        let buf = self.into_repr().0;

        for x in buf.iter() {
            w.write(&x.to_be_bytes());
        }
    }
}

impl Marshallable for Fq2 {
    fn marshal(&self, w: &mut Write) {
        self.c0.marshal(w);
        self.c1.marshal(w);
    }
}

impl Marshallable for Fq6 {
    fn marshal(&self, w: &mut Write) {
        self.c0.marshal(w);
        self.c1.marshal(w);
        self.c2.marshal(w);
    }
}

impl Marshallable for Fq12 {
    fn marshal(&self, w: &mut Write) {
        self.c0.marshal(w);
        self.c1.marshal(w);
    }
}
