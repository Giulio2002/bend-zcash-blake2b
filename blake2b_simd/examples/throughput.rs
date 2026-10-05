//! MB/s of this crate against the real blake2b_simd 1.0.4.
//!   BEND_BLAKE2B_SHADOW=0 cargo run --release --features bend --example throughput [seconds]
use std::time::Instant;

fn run(name: &str, len: usize, secs: f64, f: &dyn Fn(&[u8]) -> u8) {
    let msg: Vec<u8> = (0..len).map(|i| (i * 131 + 7) as u8).collect();
    let (mut it, t0) = (0u64, Instant::now());
    let mut sink = 0u8;
    while t0.elapsed().as_secs_f64() < secs {
        for _ in 0..8 {
            sink ^= f(&msg);
        }
        it += 8;
    }
    let t = t0.elapsed().as_secs_f64();
    println!("{:<24} {:>8} B {:>10.2} MB/s {:>10.2} us/hash  ({})", name, len, it as f64 * len as f64 / t / 1e6, t / it as f64 * 1e6, sink);
}

fn main() {
    let secs: f64 = std::env::args().nth(1).map(|s| s.parse().unwrap()).unwrap_or(2.0);
    let person = b"ZcashTxHash_\xb4\xd0\xd6\xc2";
    println!("{}", blake2b_simd::bend_stats());
    for len in [144usize, 1024, 1 << 20] {
        run("bend (this crate)", len, secs, &|m| blake2b_simd::Params::new().hash_length(32).personal(person).hash(m).as_bytes()[0]);
        run("blake2b_simd 1.0.4", len, secs, &|m| blake2b_simd_upstream::Params::new().hash_length(32).personal(person).hash(m).as_bytes()[0]);
    }
    println!("{}", blake2b_simd::bend_stats());
}
