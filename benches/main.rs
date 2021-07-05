use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn criterion_waters_benchmark(criterion: &mut Criterion) {
    use ibe::waters::*;

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
    criterion.bench_function("waters derive", move |b| b.iter(|| Identity::derive(id)));
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
    use ibe::waters_naccache::*;

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
    criterion.bench_function("waters_naccache derive", move |b| {
        b.iter(|| Identity::derive(id))
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
    use ibe::kiltz_vahlis_one::*;

    let mut rng = rand::thread_rng();

    let id = "email:w.geraedts@sarif.nl".as_bytes();
    let kid = Identity::derive(id);

    let (pk, sk) = setup(&mut rng);
    let usk = extract_usk(&pk, &sk, &kid, &mut rng);
    let ppk = pk.to_bytes();

    let (c, _k) = encrypt(&pk, &kid, &mut rng);

    criterion.bench_function("kiltz_vahlis_one unpack_pk", |b| {
        b.iter(|| PublicKey::from_bytes(&ppk))
    });
    criterion.bench_function("kiltz_vahlis_one setup", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| setup(&mut rng))
    });
    criterion.bench_function("kiltz_vahlis_one derive", move |b| {
        b.iter(|| Identity::derive(id))
    });
    criterion.bench_function("kiltz_vahlis_one extract", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| extract_usk(black_box(&pk), black_box(&sk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("kiltz_vahlis_one encrypt", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| encrypt(black_box(&pk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("kiltz_vahlis_one decrypt", move |b| {
        b.iter(|| decrypt(black_box(&usk), black_box(&c)))
    });
}

fn criterion_boyens_waters_benchmark(criterion: &mut Criterion) {
    use ibe::boyens_waters::*;

    let mut rng = rand::thread_rng();

    let id = "email:w.geraedts@sarif.nl".as_bytes();
    let kid = Identity::derive(id);

    let (pk, sk) = setup(&mut rng);
    let usk = extract_usk(&pk, &sk, &kid, &mut rng);
    let ppk = pk.to_bytes();

    let (c, _k) = encrypt(&pk, &kid, &mut rng);

    criterion.bench_function("boyens_waters unpack_pk", |b| {
        b.iter(|| PublicKey::from_bytes(&ppk))
    });
    criterion.bench_function("boyens_waters setup", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| setup(&mut rng))
    });
    criterion.bench_function("boyens_waters derive", move |b| {
        b.iter(|| Identity::derive(id))
    });
    criterion.bench_function("boyens_waters extract", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| extract_usk(black_box(&pk), black_box(&sk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("boyens_waters encrypt", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| encrypt(black_box(&pk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("boyens_waters decrypt", move |b| {
        b.iter(|| decrypt(black_box(&usk), black_box(&c)))
    });
}

criterion_group!(
    benches,
    criterion_waters_benchmark,
    criterion_waters_naccache_benchmark,
    criterion_kiltz_vahlis_one_benchmark,
    criterion_boyens_waters_benchmark,
);
criterion_main!(benches);
