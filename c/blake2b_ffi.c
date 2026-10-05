// libbendblake2b: the C ABI of the proved BLAKE2b (bend_blake2b.h).
//
// Spliced into the program's C source by the Bend compiler (the
// `import "./blake2b_ffi.c"` of the foreign effect Blake.exchange in
// entry.bend), after the Bend runtime, so every runtime symbol is in scope.
//
// The Bend program is a request loop:  req <- Blake.exchange(answer); answer = handle(req)
// A call stores a request, makes the parked Blake.exchange activation
// runnable and steps the Bend IO loop on the caller's thread until it parks on
// the next Blake.exchange. No helper thread is involved; a mutex serialises
// callers, because the Bend runtime is one global heap.
//
// Every digest byte and every chaining value comes out of the Bend program;
// this file only buffers input (the incremental API) and copies words.

#include <pthread.h>
#include "bend_blake2b.h"

#define BB_API __attribute__((visibility("default")))

enum { BB_ONESHOT = 0, BB_INIT = 1, BB_UPDATE = 2, BB_FINISH = 3 };

static pthread_mutex_t bb_lock = PTHREAD_MUTEX_INITIALIZER;
static IoWork*  bb_wait;           // the activation parked in Blake.exchange, or NULL
static int      bb_up;             // runtime initialised
static int      bb_loop_up;        // main spawned
static int      bb_have;           // a request is pending
static int      bb_sent;           // an answer came back
static u32      bb_op, bb_ll;
static u32      bb_hdr[32];
static const uint8_t* bb_key; static size_t bb_keylen;
static const uint8_t* bb_msg; static size_t bb_msglen;
static u32      bb_out[80];        // the answer words (at most 1 + 64)
static u32      bb_out_n;
static uint64_t bb_calls;

// A fresh Array<U32> of 2^d words (d >= 0) holding n bytes, little-endian packed.
static Term bb_array(Env e, const uint8_t* p, size_t n) {
  size_t words = (n + 3) / 4;
  u32 d = 0;
  while (((size_t)1 << d) < words) {
    d += 1;
  }
  Term zero = 0;
  Term arr  = blk_new(e, 0, d, 0, 1, &zero);
  if (n > 0) {
    u32* dst = (u32*)blk_ptr(e.mem, blk_loc(e.mem, arr), 0);
    memcpy(dst, p, n);
  }
  return arr;
}

// The request as Bend sees it: (op, (ll, (hdr, (key, msg)))).
static Term bb_make(Env e) {
  Term hdr = bb_array(e, (const uint8_t*)bb_hdr, sizeof bb_hdr);
  Term key = bb_array(e, bb_key, bb_keylen);
  Term msg = bb_array(e, bb_msg, bb_msglen);
  return io_tup(e, (Term)bb_op, io_tup(e, (Term)bb_ll, io_tup(e, hdr, io_tup(e, key, msg))));
}

// Blake.exchange(xs): xs is the previous answer (Nil on the first round); its
// words go to bb_out. Then the effect answers the next request, or parks the
// activation until a caller posts one.
Term bb_exchange_run(Env e, Term* f, IoWork* w) {
  Term xs = f[0];
  if (term_aux(xs) == CID_CON) {
    u32 n = 0;
    while (term_aux(xs) == CID_CON) {
      Term fb[2];
      spare_free(e, cls_fit(2), ctr_take(e, xs, 2, fb));
      if (n < sizeof bb_out / sizeof bb_out[0]) {
        bb_out[n] = (u32)fb[0];
      }
      n += 1;
      xs = fb[1];
    }
    bb_out_n = n;
    bb_sent  = 1;
  }
  if (!bb_have) {
    bb_wait = w;
    return IO_PARK;
  }
  bb_have = 0;
  return bb_make(e);
}

static void __attribute__((constructor)) bb_ffi_use(void) {
  io_eff(CID(Blake.exchange), bb_exchange_run, 0);
}

// The signal-free twin of pool_stack(): the host (Rust, Go) owns SIGSEGV.
static Term* bb_stack(void) {
  u64   len = 1ull << 31;
  char* p   = pool_mmap(len + 16384);
  if (mprotect(p + len, 16384, PROT_NONE) != 0) {
    err_fail("stack guard failed");
  }
  return (Term*)p;
}

static void bb_init_locked(void) {
  if (!bb_up) {
    corpus_setup(false, 1, 0);
    io_stk = bb_stack();
    bb_up = 1;
  }
}

// One round trip; the caller holds bb_lock and has filled the request.
static int bb_call_locked(void) {
  bb_init_locked();
  Env e = { CORPUS, ALC[0] };
  bb_sent  = 0;
  bb_calls += 1;
  if (!bb_loop_up) {
    bb_have = 1;
    Term m = corpus_eval(CORPUS, term_tsk(MAIN_FID, task_node(e, MAIN_FID, TERM_HOLE, 0, 0)));
    io_spawn(m);
    bb_loop_up = 1;
  } else {
    IoWork* a = bb_wait;
    if (a == NULL) {
      return -2;
    }
    bb_wait = NULL;
    a->item = bb_make(e);
    io_push(&io_runs, a);
  }
  while (io_runs != NULL) {
    io_step(e, io_pop(&io_runs));
  }
  bb_key = bb_msg = NULL;
  return bb_sent ? 0 : -4;
}

static void bb_put_params(u32 nn, u32 kk, const uint8_t salt[16], const uint8_t personal[16]) {
  memset(bb_hdr, 0, sizeof bb_hdr);
  bb_hdr[0] = nn;
  bb_hdr[1] = kk;
  if (salt) {
    memcpy(&bb_hdr[2], salt, 16);
  }
  if (personal) {
    memcpy(&bb_hdr[6], personal, 16);
  }
}

static void bb_put_chain(const uint64_t h[8], const uint64_t t[2]) {
  memcpy(&bb_hdr[10], h, 64);   // little-endian host: lo, hi halves
  memcpy(&bb_hdr[26], t, 16);
}

// ---------------------------------------------------------------- one-shot

BB_API int bend_blake2b(const uint8_t* key, size_t keylen, const uint8_t salt[16],
                        const uint8_t personal[16], size_t outlen, const uint8_t* msg,
                        size_t msglen, uint8_t* out) {
  if (outlen < 1 || outlen > 64 || keylen > 64 || msglen > 0xffffffffu || (keylen && !key) || (msglen && !msg)) {
    return -1;
  }
  pthread_mutex_lock(&bb_lock);
  bb_op = BB_ONESHOT;
  bb_ll = (u32)msglen;
  bb_put_params((u32)outlen, (u32)keylen, salt, personal);
  bb_key = key; bb_keylen = keylen;
  bb_msg = msg; bb_msglen = msglen;
  int r = bb_call_locked();
  if (r == 0) {
    if (bb_out_n != 1 + outlen || bb_out[0] != 1) {
      r = bb_out[0] == 0 ? -1 : -5;
    } else {
      for (size_t i = 0; i < outlen; i++) {
        out[i] = (uint8_t)bb_out[1 + i];
      }
    }
  }
  pthread_mutex_unlock(&bb_lock);
  return r;
}

// ---------------------------------------------------------------- incremental

// n full blocks at p, none of them the last; t counts the bytes before them.
static int bb_absorb(bend_blake2b_state* s, const uint8_t* p, size_t n) {
  pthread_mutex_lock(&bb_lock);
  bb_op = BB_UPDATE;
  bb_ll = 0;
  bb_put_params(s->outlen, 0, NULL, NULL);
  bb_put_chain(s->h, s->t);
  bb_hdr[30] = (u32)n;
  bb_key = NULL; bb_keylen = 0;
  bb_msg = p; bb_msglen = n * 128;
  int r = bb_call_locked();
  if (r == 0 && bb_out_n != 16) {
    r = -5;
  }
  if (r == 0) {
    memcpy(s->h, bb_out, 64);
    uint64_t add = (uint64_t)n * 128;
    s->t[0] += add;
    s->t[1] += s->t[0] < add;
  }
  pthread_mutex_unlock(&bb_lock);
  return r;
}

BB_API int bend_blake2b_init(bend_blake2b_state* s, const uint8_t* key, size_t keylen,
                             const uint8_t salt[16], const uint8_t personal[16], size_t outlen) {
  if (!s || outlen < 1 || outlen > 64 || keylen > 64 || (keylen && !key)) {
    return -1;
  }
  memset(s, 0, sizeof *s);
  s->outlen = (uint32_t)outlen;
  pthread_mutex_lock(&bb_lock);
  bb_op = BB_INIT;
  bb_ll = 0;
  bb_put_params((u32)outlen, (u32)keylen, salt, personal);
  bb_key = NULL; bb_keylen = 0;
  bb_msg = NULL; bb_msglen = 0;
  int r = bb_call_locked();
  if (r == 0 && bb_out_n != 16) {
    r = -5;
  }
  if (r == 0) {
    memcpy(s->h, bb_out, 64);
  }
  pthread_mutex_unlock(&bb_lock);
  if (r == 0 && keylen) {
    // RFC 7693 3.3: the key padded with zeros to 128 bytes is the first block.
    memcpy(s->buf, key, keylen);
    s->buflen = 128;
  }
  return r;
}

BB_API int bend_blake2b_update(bend_blake2b_state* s, const uint8_t* in, size_t inlen) {
  if (!s || (inlen && !in)) {
    return -1;
  }
  if (inlen == 0) {
    return 0;
  }
  if (s->buflen > 0) {
    size_t fill = 128 - s->buflen;
    if (fill > inlen) {
      fill = inlen;
    }
    memcpy(s->buf + s->buflen, in, fill);
    s->buflen += (uint32_t)fill;
    in += fill;
    inlen -= fill;
    if (inlen == 0) {
      return 0;   // the buffer may be full: it could still be the last block
    }
    int r = bb_absorb(s, s->buf, 1);
    if (r) {
      return r;
    }
    s->buflen = 0;
  }
  // The last 1..128 bytes stay buffered; everything before goes to Bend in
  // batches (a batch is one Bend array, so keep it bounded).
  size_t full = (inlen - 1) / 128;
  while (full > 0) {
    size_t n = full > 8192 ? 8192 : full;
    int r = bb_absorb(s, in, n);
    if (r) {
      return r;
    }
    in += n * 128;
    inlen -= n * 128;
    full -= n;
  }
  memcpy(s->buf, in, inlen);
  s->buflen = (uint32_t)inlen;
  return 0;
}

BB_API int bend_blake2b_final(const bend_blake2b_state* s, uint8_t* out) {
  if (!s || !out || s->outlen < 1 || s->outlen > 64 || s->buflen > 128) {
    return -1;
  }
  uint8_t block[128];
  memset(block, 0, sizeof block);
  memcpy(block, s->buf, s->buflen);
  pthread_mutex_lock(&bb_lock);
  bb_op = BB_FINISH;
  bb_ll = s->buflen;
  bb_put_params(s->outlen, 0, NULL, NULL);
  bb_put_chain(s->h, s->t);
  bb_key = NULL; bb_keylen = 0;
  bb_msg = block; bb_msglen = 128;
  int r = bb_call_locked();
  if (r == 0 && bb_out_n != s->outlen) {
    r = -5;
  }
  if (r == 0) {
    for (uint32_t i = 0; i < s->outlen; i++) {
      out[i] = (uint8_t)bb_out[i];
    }
  }
  pthread_mutex_unlock(&bb_lock);
  return r;
}

BB_API uint64_t bend_blake2b_calls(void) {
  return bb_calls;
}

BB_API uint64_t bend_blake2b_heap_words(void) {
  return bb_up ? (uint64_t)a32_load(a32_at(CORPUS, H_BUMP)) : 0;
}
