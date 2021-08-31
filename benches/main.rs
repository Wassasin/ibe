use criterion::{black_box, criterion_group, criterion_main, Criterion};

// This macro creates criterion functions that benchmarks a KEM given by an identifer
// TODO: small problem is that some KEM APIs differ wrt others, e.g., the extraction requires a
// public key or not. If we can fix that, we can remove a lot of code duplication.

macro_rules! bench_kem {
    ($scheme_name: ident, $fn_name: ident) => {
        fn $fn_name(criterion: &mut Criterion) {
            use ibe::kem::$scheme_name::*;

            let mut rng = rand::thread_rng();

            let id = "email:w.geraedts@sarif.nl".as_bytes();
            let kid = Identity::derive(id);

            let (pk, sk) = setup(&mut rng);
            let usk = extract_usk(&sk, &kid, &mut rng);
            let ppk = pk.to_bytes();

            let (c, _k) = encaps(&pk, &kid, &mut rng);

            criterion.bench_function(
                &format!("{} unpack_pk", stringify!($scheme_name)).to_string(),
                |b| b.iter(|| PublicKey::from_bytes(&ppk)),
            );
            criterion.bench_function(
                &format!("{} setup", stringify!($scheme_name)).to_string(),
                |b| {
                    let mut rng = rand::thread_rng();
                    b.iter(|| setup(&mut rng))
                },
            );
            criterion.bench_function(
                &format!("{} extract", stringify!($scheme_name)).to_string(),
                move |b| {
                    let mut rng = rand::thread_rng();
                    b.iter(|| extract_usk(black_box(&sk), black_box(&kid), &mut rng))
                },
            );
            criterion.bench_function(
                &format!("{} encaps", stringify!($scheme_name)).to_string(),
                move |b| {
                    let mut rng = rand::thread_rng();
                    b.iter(|| encaps(black_box(&pk), black_box(&kid), &mut rng))
                },
            );
            criterion.bench_function(
                &format!("{} decaps", stringify!($scheme_name)).to_string(),
                move |b| b.iter(|| decaps(black_box(&usk), black_box(&c))),
            );
        }
    };
}

fn criterion_waters_benchmark(criterion: &mut Criterion) {
    use ibe::pke::waters::*;

    let mut rng = rand::thread_rng();

    let id = "email:w.geraedts@sarif.nl".as_bytes();
    let kid = Identity::derive(id);

    let m = Message::generate(&mut rng);

    let (pk, sk) = setup(&mut rng);
    let usk = extract_usk(&pk, &sk, &kid, &mut rng);

    let c = encrypt(&pk, &kid, &m, &mut rng);

    criterion.bench_function("waters generate message", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| Message::generate(&mut rng))
    });
    criterion.bench_function("waters setup", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| setup(&mut rng))
    });
    criterion.bench_function("waters extract", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| extract_usk(black_box(&pk), black_box(&sk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("waters encrypt", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| encrypt(black_box(&pk), black_box(&kid), black_box(&m), &mut rng))
    });
    criterion.bench_function("waters decrypt", move |b| {
        b.iter(|| decrypt(black_box(&usk), black_box(&c)))
    });
}

fn criterion_waters_naccache_benchmark(criterion: &mut Criterion) {
    use ibe::pke::waters_naccache::*;

    let mut rng = rand::thread_rng();

    let id = "email:w.geraedts@sarif.nl".as_bytes();
    let kid = Identity::derive(id);

    let m = Message::generate(&mut rng);

    let (pk, sk) = setup(&mut rng);
    let usk = extract_usk(&pk, &sk, &kid, &mut rng);

    let c = encrypt(&pk, &kid, &m, &mut rng);

    criterion.bench_function("waters_naccache generate message", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| Message::generate(&mut rng))
    });
    criterion.bench_function("waters_naccache setup", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| setup(&mut rng))
    });
    criterion.bench_function("waters_naccache extract", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| extract_usk(black_box(&pk), black_box(&sk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("waters_naccache encrypt", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| encrypt(black_box(&pk), black_box(&kid), black_box(&m), &mut rng))
    });
    criterion.bench_function("waters_naccache decrypt", move |b| {
        b.iter(|| decrypt(black_box(&usk), black_box(&c)))
    });
}

fn criterion_kiltz_vahlis_one_benchmark(criterion: &mut Criterion) {
    use ibe::kem::kiltz_vahlis_one::*;

    let mut rng = rand::thread_rng();

    let id = "email:w.geraedts@sarif.nl".as_bytes();
    let kid = Identity::derive(id);

    let (pk, sk) = setup(&mut rng);
    let usk = extract_usk(&pk, &sk, &kid, &mut rng);
    let ppk = pk.to_bytes();

    let (c, _k) = encaps(&pk, &kid, &mut rng);

    criterion.bench_function("kiltz_vahlis_one unpack_pk", |b| {
        b.iter(|| PublicKey::from_bytes(&ppk))
    });
    criterion.bench_function("kiltz_vahlis_one setup", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| setup(&mut rng))
    });
    criterion.bench_function("kiltz_vahlis_one extract", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| extract_usk(black_box(&pk), black_box(&sk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("kiltz_vahlis_one encrypt", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| encaps(black_box(&pk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("kiltz_vahlis_one decrypt", move |b| {
        b.iter(|| decaps(black_box(&usk), black_box(&c)))
    });
}

fn criterion_cgw_kem_cca_fo_benchmark(criterion: &mut Criterion) {
    use ibe::kem::cgw_cca_fo::*;

    let mut rng = rand::thread_rng();

    let id = "email:w.geraedts@sarif.nl".as_bytes();
    let kid = Identity::derive(id);

    let (pk, sk) = setup(&mut rng);
    let usk = extract_usk(&sk, &kid, &mut rng);
    let ppk = pk.to_bytes();

    let (c, _k) = encaps(&pk, &kid, &mut rng);

    criterion.bench_function("cgw_kem_cca_fo unpack_pk", |b| {
        b.iter(|| PublicKey::from_bytes(&ppk))
    });
    criterion.bench_function("cgw_kem_cca_fo setup", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| setup(&mut rng))
    });
    criterion.bench_function("cgw_kem_cca_fo extract", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| extract_usk(black_box(&sk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("cgw_kem_cca_fo encaps", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| encaps(black_box(&pk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("cgw_kem_cca_fo decaps", move |b| {
        b.iter(|| decaps(black_box(&pk), black_box(&usk), black_box(&c)))
    });
}

fn criterion_boyen_waters_benchmark(criterion: &mut Criterion) {
    use ibe::kem::boyen_waters::*;

    let mut rng = rand::thread_rng();

    let id = "email:w.geraedts@sarif.nl".as_bytes();
    let kid = Identity::derive(id);

    let (pk, sk) = setup(&mut rng);
    let usk = extract_usk(&pk, &sk, &kid, &mut rng);
    let ppk = pk.to_bytes();

    let (c, _k) = encrypt(&pk, &kid, &mut rng);

    criterion.bench_function("boyen_waters unpack_pk", |b| {
        b.iter(|| PublicKey::from_bytes(&ppk))
    });
    criterion.bench_function("boyen_waters setup", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| setup(&mut rng))
    });
    criterion.bench_function("boyen_waters derive", move |b| {
        b.iter(|| Identity::derive(id))
    });
    criterion.bench_function("boyen_waters extract", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| extract_usk(black_box(&pk), black_box(&sk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("boyen_waters encrypt", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| encrypt(black_box(&pk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("boyen_waters decrypt", move |b| {
        b.iter(|| decrypt(black_box(&usk), black_box(&c)))
    });
}

bench_kem!(cgw_cca_kv, criterion_cgw_kem_cca_kv_benchmark);
bench_kem!(cgw_cpa, criterion_cgw_kem_cpa_benchmark);

criterion_group!(
    benches,
    criterion_waters_benchmark,
    criterion_waters_naccache_benchmark,
    criterion_kiltz_vahlis_one_benchmark,
    criterion_boyen_waters_benchmark,
    criterion_cgw_kem_cpa_benchmark,
    criterion_cgw_kem_cca_kv_benchmark,
    criterion_cgw_kem_cca_fo_benchmark,
);
criterion_main!(benches);
