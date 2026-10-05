//! `blake2b_simd` 1.0.4's public API, hashing with the proved Bend BLAKE2b.
//!
//! A drop-in replacement for the [`blake2b_simd`](https://docs.rs/blake2b_simd)
//! crate, meant for a `[patch.crates-io]`. With the `bend` feature, every
//! sequential-mode hash (any digest length, key, salt and personalization:
//! everything Zcash uses) is computed by `libbendblake2b`, the C build of the
//! BLAKE2b proved in bend-collections (`../c`). Without it, or for the tree-mode
//! parameters (fanout, depth, leaf length, node offset/depth, inner length, last
//! node), the hash is the original `blake2b_simd` 1.0.4 code, vendored in
//! `reference/`. `blake2bp` is always the original code; `many` takes this
//! crate's `Params` and `State` and hashes its inputs one after another.
//!
//! Runtime switches (environment, read once):
//! - `BEND_BLAKE2B=0`: use the original code even with the `bend` feature.
//! - `BEND_BLAKE2B_SHADOW=0`: turn the shadow off. The shadow is on by default:
//!   every Bend hash is recomputed with the original code; a mismatch is
//!   counted, logged (parameters and input length) and the original digest is
//!   returned, so the caller never sees a wrong hash.
//! - `BEND_BLAKE2B_STATS=<file>`: rewrite the counters to this file every
//!   65536 hashes. They are also printed to stderr every 2^22 hashes;
//!   [`bend_stats`] reads them in process.

#![cfg_attr(not(feature = "bend"), allow(dead_code))]

use core::fmt;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::OnceLock;

#[allow(dead_code, clippy::all)]
mod reference;

pub mod many;
pub use reference::{blake2bp, Hash, BLOCKBYTES, KEYBYTES, OUTBYTES, PERSONALBYTES, SALTBYTES};

#[cfg(feature = "bend")]
mod ffi {
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct State {
        pub h: [u64; 8],
        pub t: [u64; 2],
        pub buf: [u8; 128],
        pub buflen: u32,
        pub outlen: u32,
    }

    unsafe extern "C" {
        pub fn bend_blake2b_init(
            s: *mut State,
            key: *const u8,
            keylen: usize,
            salt: *const u8,
            personal: *const u8,
            outlen: usize,
        ) -> i32;
        pub fn bend_blake2b_update(s: *mut State, input: *const u8, len: usize) -> i32;
        pub fn bend_blake2b_final(s: *const State, out: *mut u8) -> i32;
    }
}

// ---------------------------------------------------------------- counters

static HASHES: AtomicU64 = AtomicU64::new(0);
static MISMATCHES: AtomicU64 = AtomicU64::new(0);
static FALLBACKS: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicU64 = AtomicU64::new(0);

/// The shim's counters since the process started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Digests computed by the Bend BLAKE2b.
    pub hashes: u64,
    /// Bend digests that differed from the shadow (the shadow's was returned).
    pub mismatches: u64,
    /// States that used the original code although Bend was on (tree-mode parameters).
    pub fallbacks: u64,
    /// Bend library calls that returned an error (the original code took over).
    pub errors: u64,
    /// Whether Bend hashing is on.
    pub bend: bool,
    /// Whether the shadow is on.
    pub shadow: bool,
}

/// Reads the counters.
pub fn bend_stats() -> Stats {
    let c = config();
    Stats {
        hashes: HASHES.load(Relaxed),
        mismatches: MISMATCHES.load(Relaxed),
        fallbacks: FALLBACKS.load(Relaxed),
        errors: ERRORS.load(Relaxed),
        bend: c.bend,
        shadow: c.shadow,
    }
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "bend-blake2b: bend={} shadow={} hashes={} mismatches={} fallbacks={} errors={}",
            self.bend, self.shadow, self.hashes, self.mismatches, self.fallbacks, self.errors
        )
    }
}

struct Config {
    bend: bool,
    shadow: bool,
    stats_file: Option<String>,
}

fn config() -> &'static Config {
    static C: OnceLock<Config> = OnceLock::new();
    C.get_or_init(|| {
        let off = |k: &str| std::env::var(k).map(|v| v == "0").unwrap_or(false);
        Config {
            bend: cfg!(feature = "bend") && !off("BEND_BLAKE2B"),
            shadow: !off("BEND_BLAKE2B_SHADOW"),
            stats_file: std::env::var("BEND_BLAKE2B_STATS").ok().filter(|s| !s.is_empty()),
        }
    })
}

fn counted(n: u64) {
    if n % (1 << 16) == 0 {
        if let Some(path) = &config().stats_file {
            let _ = std::fs::write(path, format!("{}\n", bend_stats()));
        }
    }
    if n % (1 << 22) == 0 {
        eprintln!("{}", bend_stats());
    }
}

// ---------------------------------------------------------------- Params

/// A parameter builder, as `blake2b_simd::Params`.
#[derive(Clone)]
pub struct Params {
    inner: reference::Params,
}

impl Params {
    /// Equivalent to `Params::default()`.
    #[inline]
    pub fn new() -> Self {
        Params { inner: reference::Params::new() }
    }

    /// Hash an input all at once with these parameters.
    #[inline]
    pub fn hash(&self, input: &[u8]) -> Hash {
        let mut s = self.to_state();
        s.update(input);
        s.finalize()
    }

    /// Construct a `State` object based on these parameters.
    pub fn to_state(&self) -> State {
        State::with_params(self)
    }

    /// Set the length of the final hash in bytes, from 1 to `OUTBYTES` (64). Apart from
    /// controlling the length of the final `Hash`, this is also associated data, and changing it
    /// will result in a totally different hash.
    #[inline]
    pub fn hash_length(&mut self, length: usize) -> &mut Self {
        self.inner.hash_length(length);
        self
    }

    /// Use a secret key, so that BLAKE2 acts as a MAC. The maximum key length is `KEYBYTES`
    /// (64). An empty key is equivalent to having no key at all.
    #[inline]
    pub fn key(&mut self, key: &[u8]) -> &mut Self {
        self.inner.key(key);
        self
    }

    /// At most `SALTBYTES` (16). Shorter salts are padded with null bytes. An empty salt is
    /// equivalent to having no salt at all.
    #[inline]
    pub fn salt(&mut self, salt: &[u8]) -> &mut Self {
        self.inner.salt(salt);
        self
    }

    /// At most `PERSONALBYTES` (16). Shorter personalizations are padded with null bytes. An empty
    /// personalization is equivalent to having no personalization at all.
    #[inline]
    pub fn personal(&mut self, personalization: &[u8]) -> &mut Self {
        self.inner.personal(personalization);
        self
    }

    /// From 0 (meaning unlimited) to 255. The default is 1 (meaning sequential).
    #[inline]
    pub fn fanout(&mut self, fanout: u8) -> &mut Self {
        self.inner.fanout(fanout);
        self
    }

    /// From 0 (meaning BLAKE2X B2 hashes), through 1 (the default, meaning sequential) to 255 (meaning unlimited).
    #[inline]
    pub fn max_depth(&mut self, depth: u8) -> &mut Self {
        self.inner.max_depth(depth);
        self
    }

    /// From 0 (the default, meaning unlimited or sequential) to `2^32 - 1`.
    #[inline]
    pub fn max_leaf_length(&mut self, length: u32) -> &mut Self {
        self.inner.max_leaf_length(length);
        self
    }

    /// From 0 (the default, meaning first, leftmost, leaf, or sequential) to `2^64 - 1`.
    #[inline]
    pub fn node_offset(&mut self, offset: u64) -> &mut Self {
        self.inner.node_offset(offset);
        self
    }

    /// From 0 (the default, meaning leaf or sequential) to 255.
    #[inline]
    pub fn node_depth(&mut self, depth: u8) -> &mut Self {
        self.inner.node_depth(depth);
        self
    }

    /// From 0 (the default, meaning sequential) to `OUTBYTES` (64).
    #[inline]
    pub fn inner_hash_length(&mut self, length: usize) -> &mut Self {
        self.inner.inner_hash_length(length);
        self
    }

    /// Indicates the rightmost node in a row. This can also be changed on the
    /// `State` object, potentially after hashing has begun. See
    /// [`State::set_last_node`].
    #[inline]
    pub fn last_node(&mut self, last_node: bool) -> &mut Self {
        self.inner.last_node(last_node);
        self
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Params {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}

// ---------------------------------------------------------------- State

/// What a mismatch report needs: the parameters, never the key itself.
#[derive(Clone, Copy)]
struct Desc {
    hash_length: u8,
    key_length: u8,
    salt: [u8; SALTBYTES],
    personal: [u8; PERSONALBYTES],
}

/// An incremental hasher for BLAKE2b, as `blake2b_simd::State`.
#[derive(Clone)]
pub struct State {
    /// The original code: the shadow, or the whole hash when Bend is off.
    inner: Option<reference::State>,
    #[cfg(feature = "bend")]
    bend: Option<ffi::State>,
    count: u128,
    desc: Desc,
}

impl State {
    /// Equivalent to `State::default()` or `Params::default().to_state()`.
    pub fn new() -> Self {
        Self::with_params(&Params::default())
    }

    fn with_params(params: &Params) -> Self {
        let mut desc = Desc { hash_length: 64, key_length: 0, salt: [0; SALTBYTES], personal: [0; PERSONALBYTES] };
        let seq = params.inner.sequential();
        if let Some((nn, key, salt, personal)) = seq {
            desc = Desc { hash_length: nn as u8, key_length: key.len() as u8, salt: *salt, personal: *personal };
        }
        #[cfg(feature = "bend")]
        {
            let c = config();
            if c.bend {
                if let Some((nn, key, salt, personal)) = seq {
                    let mut s = ffi::State { h: [0; 8], t: [0; 2], buf: [0; 128], buflen: 0, outlen: 0 };
                    let r = unsafe {
                        ffi::bend_blake2b_init(&mut s, key.as_ptr(), key.len(), salt.as_ptr(), personal.as_ptr(), nn)
                    };
                    if r == 0 {
                        let inner = if c.shadow { Some(params.inner.to_state()) } else { None };
                        return State { inner, bend: Some(s), count: 0, desc };
                    }
                    ERRORS.fetch_add(1, Relaxed);
                } else {
                    FALLBACKS.fetch_add(1, Relaxed);
                }
            }
        }
        State {
            inner: Some(params.inner.to_state()),
            #[cfg(feature = "bend")]
            bend: None,
            count: 0,
            desc,
        }
    }

    /// Add input to the hash. You can call `update` any number of times.
    pub fn update(&mut self, input: &[u8]) -> &mut Self {
        self.count += input.len() as u128;
        #[cfg(feature = "bend")]
        if let Some(s) = &mut self.bend {
            let r = unsafe { ffi::bend_blake2b_update(s, input.as_ptr(), input.len()) };
            if r != 0 {
                ERRORS.fetch_add(1, Relaxed);
                assert!(self.inner.is_some(), "bend_blake2b_update failed ({}) with the shadow off", r);
                self.bend = None;
            }
        }
        if let Some(i) = &mut self.inner {
            i.update(input);
        }
        self
    }

    /// Finalize the state and return a `Hash`. This method is idempotent, and calling it multiple
    /// times will give the same result. It's also possible to `update` with more input in between.
    pub fn finalize(&self) -> Hash {
        #[cfg(feature = "bend")]
        if let Some(s) = &self.bend {
            let mut out = [0u8; OUTBYTES];
            let r = unsafe { ffi::bend_blake2b_final(s, out.as_mut_ptr()) };
            if r == 0 {
                let got = Hash::from_parts(out, self.desc.hash_length as usize);
                let n = HASHES.fetch_add(1, Relaxed) + 1;
                let result = match &self.inner {
                    Some(i) => {
                        let want = i.finalize();
                        if want != got {
                            MISMATCHES.fetch_add(1, Relaxed);
                            eprintln!(
                                "bend-blake2b MISMATCH hash_length={} key_length={} salt={} personal={} input_length={}",
                                self.desc.hash_length,
                                self.desc.key_length,
                                hex(&self.desc.salt),
                                hex(&self.desc.personal),
                                self.count
                            );
                        }
                        want
                    }
                    None => got,
                };
                counted(n);
                return result;
            }
            ERRORS.fetch_add(1, Relaxed);
            assert!(self.inner.is_some(), "bend_blake2b_final failed ({}) with the shadow off", r);
        }
        self.inner.as_ref().expect("a state without Bend keeps the original").finalize()
    }

    /// Set a flag indicating that this is the last node of its level in a tree hash. This is
    /// equivalent to [`Params::last_node`], except that it can be set at any time before calling
    /// `finalize`. That allows callers to begin hashing a node without knowing ahead of time
    /// whether it's the last in its level. For more details about the intended use of this flag
    /// [the BLAKE2 spec].
    ///
    /// Tree hashing is not done by Bend: a Bend state switches to its shadow, so
    /// with the shadow off this panics once hashing has begun.
    ///
    /// [the BLAKE2 spec]: https://blake2.net/blake2.pdf
    pub fn set_last_node(&mut self, last_node: bool) -> &mut Self {
        #[cfg(feature = "bend")]
        if last_node && self.bend.is_some() {
            assert!(
                self.inner.is_some(),
                "set_last_node(true) on a Bend state needs BEND_BLAKE2B_SHADOW=1 (or BEND_BLAKE2B=0)"
            );
            self.bend = None;
            FALLBACKS.fetch_add(1, Relaxed);
        }
        if let Some(i) = &mut self.inner {
            i.set_last_node(last_node);
        }
        self
    }

    /// Return the total number of bytes input so far.
    ///
    /// Note that `count` doesn't include the bytes of the key block, if any.
    /// It's exactly the total number of input bytes fed to `update`.
    pub fn count(&self) -> u128 {
        self.count
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

impl std::io::Write for State {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(feature = "bend")]
        let bend = self.bend.is_some();
        #[cfg(not(feature = "bend"))]
        let bend = false;
        write!(f, "State {{ count: {}, hash_length: {}, bend: {} }}", self.count, self.desc.hash_length, bend)
    }
}

impl Default for State {
    fn default() -> Self {
        Self::with_params(&Params::default())
    }
}

/// Compute the BLAKE2b hash of a slice of bytes all at once, using default
/// parameters.
pub fn blake2b(input: &[u8]) -> Hash {
    Params::new().hash(input)
}

/// As `blake2b_simd::benchmarks`.
pub mod benchmarks {
    pub use crate::reference::benchmarks::force_portable_blake2bp;

    /// Force the original code's portable implementation (Bend is unaffected).
    pub fn force_portable(params: &mut super::Params) {
        crate::reference::benchmarks::force_portable(&mut params.inner)
    }
}

#[cfg(test)]
mod tests;
