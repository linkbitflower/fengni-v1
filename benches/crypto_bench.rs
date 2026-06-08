//! Criterion benchmarks for fengni cryptographic operations.
//!
//! Pattern from boringtun's `benches/crypto_benches/`.
//!
//! Run with:
//!   cargo bench

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use fengni::crypto::{self, CipherState, KeyPair, PUBLIC_KEY_LEN, SYMMETRIC_KEY_LEN};
use fengni::HandshakeBuilder;

fn bench_handshake_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    group.sample_size(200);

    let _alice_static = KeyPair::generate();
    let _bob_static = KeyPair::generate();

    group.bench_function("full_handshake_roundtrip", |b| {
        b.iter(|| {
            let mut alice_key = KeyPair::generate();
            let bob_key = KeyPair::generate();
            let bob_pub = bob_key.public_key_bytes();
            alice_key.pin_peer(&bob_pub);

            let mut hs_a = HandshakeBuilder::initiator(alice_key, bob_pub).build();
            let mut hs_b = HandshakeBuilder::responder(bob_key).build();

            let hello = hs_a.send_hello().unwrap();
            let reply = hs_b.handle_message(&hello).unwrap().unwrap();
            let auth = hs_a.handle_message(&reply).unwrap().unwrap();
            let finish = hs_b.handle_message(&auth).unwrap().unwrap();
            hs_a.handle_message(&finish).unwrap();
        })
    });

    group.finish();
}

fn bench_encrypt_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");

    for size in [64, 256, 1024, 8192, 65535] {
        group.throughput(Throughput::Bytes(size as u64));

        let key_bytes = [0xAAu8; SYMMETRIC_KEY_LEN];
        let plaintext = vec![0xBBu8; size];

        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305_encrypt", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let nonce_bytes = [0u8; crypto::NONCE_LEN];
                    black_box(crypto::encrypt(&key_bytes, &nonce_bytes, &plaintext).unwrap())
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("cipherstate_encrypt", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut cs = CipherState::new(&key_bytes);
                    black_box(cs.encrypt(&plaintext).unwrap())
                })
            },
        );
    }

    group.finish();
}

fn bench_decrypt_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt");

    for size in [64, 256, 1024, 8192, 65535] {
        group.throughput(Throughput::Bytes(size as u64));

        let key_bytes = [0xAAu8; SYMMETRIC_KEY_LEN];
        let plaintext = vec![0xBBu8; size];
        let mut cs = CipherState::new(&key_bytes);
        let ciphertext = cs.encrypt(&plaintext).unwrap();

        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305_decrypt", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let nonce_bytes = [0u8; crypto::NONCE_LEN];
                    black_box(crypto::decrypt(&key_bytes, &nonce_bytes, &ciphertext).unwrap())
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("cipherstate_decrypt", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut cs = CipherState::new(&key_bytes);
                    black_box(cs.decrypt(&ciphertext).unwrap())
                })
            },
        );
    }

    group.finish();
}

fn bench_replay_validator(c: &mut Criterion) {
    let mut group = c.benchmark_group("replay");
    group.sample_size(5000);

    group.bench_function("will_accept_mark_did_receive", |b| {
        b.iter(|| {
            let mut r = crypto::ReplayValidator::new();
            for i in 0..100 {
                r.will_accept(i).unwrap();
                r.mark_did_receive(i);
            }
        })
    });

    group.finish();
}

fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf");
    group.sample_size(5000);

    let ikm = [0x42u8; PUBLIC_KEY_LEN];
    let info = b"fengni-v1-transport-send";

    group.bench_function("derive_key_hkdf_sha256", |b| {
        b.iter(|| black_box(crypto::derive_key(&ikm, info).unwrap()))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_handshake_full,
    bench_encrypt_throughput,
    bench_decrypt_throughput,
    bench_replay_validator,
    bench_key_derivation,
);
criterion_main!(benches);
