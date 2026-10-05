# bend-zcash-blake2b

BLAKE2b for Zcash, computed by a **formally proved** implementation written in
[Bend](https://bend-lang.com), packaged as a C library and as a drop-in
replacement for the Rust `blake2b_simd` crate.

| Part | Where | What |
|---|---|---|
| Proved BLAKE2b | [`bend-collections/`](https://github.com/Giulio2002/bend-collections/tree/blake2b-params) (submodule, branch `blake2b-params`) | RFC 7693 sequential mode with the full parameter block: digest length 1..64, key 0..64 bytes, 16-byte salt and personalization. `src/crypto/blake/blake2b/params.bend` is proved equal to the specification `spec/crypto/blake/blake2b.bend` (`S.blake2b_params`) for every input: law `blake2b_params_correct` in `proofs/crypto/blake/blake2b/`. |
| C library | [`c/`](c) | `libbendblake2b`: one-shot and incremental BLAKE2b, [`bend_blake2b.h`](c/bend_blake2b.h). |
| Rust drop-in | [`blake2b_simd/`](blake2b_simd) | Package `blake2b_simd` 1.0.4 with the original's public API (`Params`, `State`, `Hash`, `blake2b`, `many`, `blake2bp`, constants), for a `[patch.crates-io]`; feature `bend` hashes with the C library, with an optional shadow check. |

## C API

```c
#include "bend_blake2b.h"

// one-shot: the whole computation is the proved P.blake2b_params
int bend_blake2b(const uint8_t *key, size_t keylen, const uint8_t salt[16],
                 const uint8_t personal[16], size_t outlen,
                 const uint8_t *msg, size_t msglen, uint8_t *out);

// incremental: the state is a plain struct, copying it forks the hash
int bend_blake2b_init(bend_blake2b_state *s, const uint8_t *key, size_t keylen,
                      const uint8_t salt[16], const uint8_t personal[16], size_t outlen);
int bend_blake2b_update(bend_blake2b_state *s, const uint8_t *in, size_t inlen);
int bend_blake2b_final(const bend_blake2b_state *s, uint8_t *out);
```

Return values: 0 success, -1 invalid parameters (`outlen` not in 1..64, `keylen`
above 64, a NULL pointer with a non-zero length), below -1 a runtime error.
`salt` and `personal` may be NULL (zeros). Calls are thread-safe and serialised
by one lock (the Bend runtime has one heap).

How it is built: `c/entry.bend` is a request loop around the proved functions,
`c/blake2b_ffi.c` is a Bend foreign effect plus the C ABI, spliced in by the
Bend compiler. `c/bendblake2b.c` is the C that Bend 2.0.34 generates from them
(checked in, so building needs only a C compiler; `make regen` regenerates it
byte for byte).

```sh
git clone --recursive https://github.com/Giulio2002/bend-zcash-blake2b
cd bend-zcash-blake2b/c
make                       # build/libbendblake2b.{a,so}
make check                 # hashlib + BLAKE2 KAT vectors, one-shot and incremental
```

### What is proved and what is not

- Proved (Bend's checker; the existing compression proofs are reused): for every
  digest length, key, salt, personalization and message,
  `P.blake2b_params == S.blake2b_params`, the RFC 7693 specification, including
  the initial chaining value `IV xor parameter block`, the key block and the
  truncation to `nn` bytes. The one-shot `bend_blake2b` is exactly this function.
- The incremental API composes proved pieces (`P.init`, the block absorption
  `P.update` over `B.absorb`, the last block `P.finish` over `B.final`); the
  buffering between them (which bytes are held back as the last block, the
  byte counter, the key block prepended to the input) is C in
  `blake2b_ffi.c`, tested but not proved.
- The C glue (copying words in and out) and Bend's C backend are trusted.

### Tests

All expected digests are computed independently of this code.

| Check | Source of truth | Result |
|---|---|---|
| `make check` (`check.c`) | 256 BLAKE2 reference keyed KATs, 3000 random parameter combinations and long (64 KiB, 1 MiB) messages from Python `hashlib.blake2b(digest_size=, key=, salt=, person=)`, each through the one-shot call, the incremental API in 5 chunkings and a forked state; invalid parameters | 25,749 checks, 0 failures |
| `check_zip244.py` | the ZIP-244 vectors of [zcash-test-vectors](https://github.com/zcash/zcash-test-vectors) (`test-vectors/json/zip_0244.json`): the upstream generator is run with `hashlib.blake2b` replaced by this library and its output compared with the published file | 10 NU5 transactions, 62 digests (txid, auth digest, sighashes) equal |
| `check_equihash.py` | the equihash crate's test vectors (librustzcash `components/equihash/src/test_vectors/`), verified with the crate's algorithm hashing through this library ("ZcashPoW" + n + k) | 46 valid solutions accepted incl. (200,9), mutated solutions and 9 invalid vectors rejected with the crate's error kind |
| `cargo test --features bend` (`blake2b_simd/`) | the real `blake2b_simd` 1.0.4 from crates.io | 1500 random parameter sets with split inputs, Equihash-style cloned states, tree-mode fallback, upstream's own unit tests and doctests |
| `bend-collections/tests/crypto/blake/blake2b/params.bend` | BLAKE2 KATs and hashlib, run in Bend | 400 rows, 0 failures |

## Rust: `blake2b_simd` drop-in

```toml
[patch.crates-io]
blake2b_simd = { git = "https://github.com/Giulio2002/bend-zcash-blake2b" }
```

and enable the `bend` feature of `blake2b_simd` somewhere in the graph
(features unify). Needs `clang` 14+ to compile `c/bendblake2b.c`.

- `BEND_BLAKE2B=0`: hash with the original code.
- `BEND_BLAKE2B_SHADOW=0`: no shadow. **The shadow is on by default**: each
  Bend digest is recomputed with the original `blake2b_simd`; a mismatch is
  counted and logged (parameters, input length; never the key or input) and the
  original digest is returned.
- `BEND_BLAKE2B_STATS=<file>`: counters written there every 65536 hashes;
  `blake2b_simd::bend_stats()` in process.

Tree-mode parameters (fanout, depth, leaf length, node offset/depth, inner hash
length, last node) and `blake2bp` use the original code; Zcash uses none of
them.

## Throughput

One core of a shared 48-thread Intel Xeon Gold 5412U (loaded by other jobs, so the 1 MiB
figures vary between runs), digest 32 bytes, personalization `ZcashTxHash_`:

| Message | Bend (C API, one-shot) | Bend (Rust shim) | `blake2b_simd` 1.0.4 | libsodium |
|---|---|---|---|---|
| 144 B (an Equihash input) | 36 MB/s (4.0 µs) | 36 MB/s (4.0 µs) | 494 MB/s (0.29 µs) | 418 MB/s (0.34 µs) |
| 1 KiB | 119 MB/s | 153 MB/s | 926 MB/s | 815 MB/s |
| 1 MiB | 170–300 MB/s | 298 MB/s | 952 MB/s | 860 MB/s |

Large inputs run at about a third of the SIMD implementations' speed. Small ones
are dominated by a fixed cost of about 3–4 µs per call to the Bend runtime
(building the request arrays, the IO loop round trip).

`make bench` (C, needs `libsodium.so.23`);
`BEND_BLAKE2B_SHADOW=0 cargo run --release --features bend --example throughput`
in `blake2b_simd/`.
