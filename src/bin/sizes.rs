//! This file produces a binary that prints the sizes of several IBE/KEM components
//! such as the MPK, MSK, USK, CT.

macro_rules! print_sizes_kem {
    ($scheme_name: ident) => {{
        use ibe::kem::$scheme_name::*;

        let mut rng = rand::thread_rng();
        let id = "email:w.geraedts@sarif.nl".as_bytes();
        let kid = Identity::derive(id);

        let (pk, sk) = setup(&mut rng);
        let usk = extract_usk(&sk, &kid, &mut rng);
        let (c, _k) = encaps(&pk, &kid, &mut rng);

        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();
        let usk_bytes = usk.to_bytes();
        let ct_bytes = c.to_bytes();

        println!(stringify!($scheme_name));
        println!("MPK:\t{}", pk_bytes.len());
        println!("MSK:\t{}", sk_bytes.len());
        println!("USK:\t{}", usk_bytes.len());
        println!("CT:\t{}\n", ct_bytes.len());
    }};
}

/// Call conventions are slightly different for this scheme
fn print_size_kiltz_vahlis_one() {
    use ibe::kem::kiltz_vahlis_one::*;
    let mut rng = rand::thread_rng();

    let id = "email:w.geraedts@sarif.nl".as_bytes();
    let kid = Identity::derive(id);

    let (pk, sk) = setup(&mut rng);
    let usk = extract_usk(&pk, &sk, &kid, &mut rng);
    let (c, _k) = encaps(&pk, &kid, &mut rng);

    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();
    let usk_bytes = usk.to_bytes();
    let ct_bytes = c.to_bytes();

    println!("kiltz_vahlis_one");
    println!("MPK:\t{}", pk_bytes.len());
    println!("MSK:\t{}", sk_bytes.len());
    println!("USK:\t{}", usk_bytes.len());
    println!("CT:\t{}\n", ct_bytes.len());
}

fn main() {
    println!("Sizes in bytes:\n");
    print_size_kiltz_vahlis_one();

    print_sizes_kem!(cgw_cpa);
    print_sizes_kem!(cgw_cca_fo);
    print_sizes_kem!(cgw_cca_kv);
}
