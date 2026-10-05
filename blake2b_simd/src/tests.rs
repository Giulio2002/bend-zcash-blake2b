// The shim against the real blake2b_simd 1.0.4 from crates.io (dev-dependency
// `blake2b_simd_upstream`): same digests, counts and hex for random parameters,
// split inputs, cloned states and the tree-mode fallback. With the `bend` feature
// the digests come from libbendblake2b; the tests turn the shadow off so a wrong
// Bend digest cannot be masked by the shadow's.
use super::*;
use blake2b_simd_upstream as up;

fn no_shadow() {
    // config() is read once per process; set before the first hash.
    unsafe { std::env::set_var("BEND_BLAKE2B_SHADOW", "0") };
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn random_parameters_and_splits() {
    no_shadow();
    let mut r = Rng(0x5eed_b1a4e);
    for i in 0..1500 {
        let nn = 1 + r.below(64);
        let key = { let n = [0, 0, 1, 32, 64, r.below(65)][r.below(6)]; r.bytes(n) };
        let salt = { let n = [0, 16, r.below(17)][r.below(3)]; r.bytes(n) };
        let person = match r.below(4) {
            0 => b"ZcashPoW\xc8\x00\x00\x00\x09\x00\x00\x00".to_vec(),
            1 => b"ZcashTxHash_\xb4\xd0\xd6\xc2".to_vec(),
            2 => vec![],
            _ => { let n = r.below(17); r.bytes(n) }
        };
        let len = [0, 1, 127, 128, 129, 140, 144, 256, r.below(3000)][r.below(9)];
        let msg = r.bytes(len);
        let want = up::Params::new().hash_length(nn).key(&key).salt(&salt).personal(&person).hash(&msg);
        let p = { let mut p = Params::new(); p.hash_length(nn).key(&key).salt(&salt).personal(&person); p };
        assert_eq!(p.hash(&msg).as_bytes(), want.as_bytes(), "one-shot case {}", i);
        let mut s = p.to_state();
        let mut at = 0;
        while at < msg.len() {
            let n = (1 + r.below(300)).min(msg.len() - at);
            s.update(&msg[at..at + n]);
            at += n;
        }
        assert_eq!(s.count(), msg.len() as u128);
        let got = s.finalize();
        assert_eq!(got.as_bytes(), want.as_bytes(), "split case {}", i);
        assert_eq!(got.to_hex().as_str(), want.to_hex().as_str());
        assert_eq!(got.as_bytes().len(), nn);
        assert_eq!(s.finalize(), got, "finalize is idempotent");
    }
}

#[test]
fn equihash_style_clones() {
    no_shadow();
    // The equihash crate: one state over header + nonce, cloned for each index.
    let person = b"ZcashPoW\xc8\x00\x00\x00\x09\x00\x00\x00";
    let header: Vec<u8> = (0..140u32).map(|i| (i * 7 + 3) as u8).collect();
    let mut base = Params::new().hash_length(50).personal(person).to_state();
    base.update(&header);
    let mut ubase = up::Params::new().hash_length(50).personal(person).to_state();
    ubase.update(&header);
    for i in 0u32..600 {
        let mut s = base.clone();
        s.update(&i.to_le_bytes());
        let mut u = ubase.clone();
        u.update(&i.to_le_bytes());
        assert_eq!(s.finalize().as_bytes(), u.finalize().as_bytes(), "index {}", i);
    }
}

#[test]
fn defaults_and_helpers() {
    no_shadow();
    for len in [0usize, 3, 128, 1000] {
        let m = vec![0xabu8; len];
        assert_eq!(blake2b(&m).as_bytes(), up::blake2b(&m).as_bytes());
        assert_eq!(State::new().update(&m).finalize(), Hash::from(*up::blake2b(&m).as_array()));
        let mut w = State::default();
        std::io::Write::write_all(&mut w, &m).unwrap();
        assert_eq!(w.finalize().as_bytes(), up::blake2b(&m).as_bytes());
    }
    assert_eq!(
        format!("{:?}", Params::new().hash_length(16)),
        format!("{:?}", up::Params::new().hash_length(16))
    );
}

#[test]
fn tree_mode_uses_the_original() {
    no_shadow();
    let m = vec![7u8; 500];
    let ours = Params::new().fanout(2).max_depth(2).node_offset(1).inner_hash_length(32).last_node(true).hash(&m);
    let theirs = up::Params::new().fanout(2).max_depth(2).node_offset(1).inner_hash_length(32).last_node(true).hash(&m);
    assert_eq!(ours.as_bytes(), theirs.as_bytes());
    assert_eq!(blake2bp::blake2bp(&m).as_bytes(), up::blake2bp::blake2bp(&m).as_bytes());
}

#[test]
#[should_panic]
fn invalid_hash_length_panics_like_the_original() {
    Params::new().hash_length(65);
}

#[cfg(feature = "bend")]
#[test]
fn bend_is_used() {
    no_shadow();
    let before = bend_stats().hashes;
    Params::new().personal(b"ZcashTxHash_").hash(b"abc");
    let s = bend_stats();
    assert!(s.bend, "the bend feature is on but Bend hashing is off");
    assert!(s.hashes > before, "no hash went through libbendblake2b");
    assert_eq!(s.mismatches, 0);
}
