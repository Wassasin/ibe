use criterion::{black_box, criterion_group, criterion_main, Criterion};
use waters::*;

fn criterion_benchmark(criterion: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let id = "email:w.geraedts@sarif.nl".as_bytes();
    let kid = Identity::derive(id);

    let m = Message::generate(&mut rng);

    let (pk, sk) = setup(&mut rng);
    let usk = extract_usk(&pk, &sk, &kid, &mut rng);

    let c = encrypt(&pk, &kid, &m, &mut rng);

    criterion.bench_function("generate message", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| Message::generate(&mut rng))
    });
    criterion.bench_function("setup", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| setup(&mut rng))
    });
    criterion.bench_function("derive", move |b| b.iter(|| Identity::derive(id)));
    criterion.bench_function("extract", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| extract_usk(black_box(&pk), black_box(&sk), black_box(&kid), &mut rng))
    });
    criterion.bench_function("encrypt", move |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| encrypt(black_box(&pk), black_box(&kid), black_box(&m), &mut rng))
    });
    criterion.bench_function("decrypt", move |b| {
        b.iter(|| decrypt(black_box(&usk), black_box(&c)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
