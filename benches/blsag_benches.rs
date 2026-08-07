use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use nazgul::blsag::BLSAG;
use nazgul::ring::Ring;
use nazgul::traits::SignRef;
use rand_core::OsRng;
use sha2::Sha512;
use std::time::Duration;

// Helper to set up a ring for signing.
fn setup_ring(num_decoys: usize) -> (Scalar, Ring) {
    let mut csprng = OsRng;
    let signer_private_key = Scalar::random(&mut csprng);
    let signer_public_key =
        signer_private_key * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    let mut public_keys: Vec<RistrettoPoint> = (0..num_decoys)
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();

    public_keys.push(signer_public_key);
    let ring = Ring::new(public_keys);

    (signer_private_key, ring)
}

fn blsag_sign_benchmark(c: &mut Criterion) {
    let message: &[u8] = b"This is a benchmark message.";
    let ring_size: usize = 2_000;

    let (private_key, ring) = setup_ring(ring_size - 1);
    let precomputed_data = ring.precompute::<Sha512>();

    let mut group = c.benchmark_group("BLSAG Signing");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    group.bench_with_input("No Precomputation", &ring, |b, r| {
        b.iter(|| BLSAG::sign::<Sha512, OsRng>(private_key, r, None, message).unwrap());
    });

    group.bench_with_input("With Precomputation", &ring, |b, r| {
        b.iter(|| {
            BLSAG::sign::<Sha512, OsRng>(private_key, r, Some(&precomputed_data), message).unwrap()
        });
    });

    group.finish();
}

criterion_group!(benches, blsag_sign_benchmark);
criterion_main!(benches);
