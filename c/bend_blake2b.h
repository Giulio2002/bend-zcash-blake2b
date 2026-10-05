// libbendblake2b: BLAKE2b (RFC 7693, sequential mode) computed by the proved
// Bend implementation of bend-collections (src/crypto/blake/blake2b/params.bend).
//
// Every function returns 0 on success, -1 for invalid parameters (outlen not
// in 1..64, keylen above 64, a NULL pointer with a non-zero length) and a
// value below -1 for a runtime error. salt and personal may be NULL (sixteen
// zero bytes). Calls are thread-safe and serialised by one internal lock.
#ifndef BEND_BLAKE2B_H
#define BEND_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// The outlen-byte digest of msg under the key, salt and personalization.
// The whole computation is the proved P.blake2b_params.
int bend_blake2b(const uint8_t* key, size_t keylen, const uint8_t salt[16],
                 const uint8_t personal[16], size_t outlen, const uint8_t* msg,
                 size_t msglen, uint8_t* out);

// Incremental hashing. The state is a plain value: copying it forks the hash.
// The chaining value comes from the proved P.init, full blocks go through the
// proved block absorption (P.update) and the last block through P.finish; the
// buffering in between is C.
typedef struct {
  uint64_t h[8];      // chaining value
  uint64_t t[2];      // bytes compressed so far (128-bit counter)
  uint8_t  buf[128];  // pending bytes, the last block until more input arrives
  uint32_t buflen;
  uint32_t outlen;
} bend_blake2b_state;

int bend_blake2b_init(bend_blake2b_state* s, const uint8_t* key, size_t keylen,
                      const uint8_t salt[16], const uint8_t personal[16], size_t outlen);
int bend_blake2b_update(bend_blake2b_state* s, const uint8_t* in, size_t inlen);
// Writes s->outlen bytes; s is left unchanged (final can be called again).
int bend_blake2b_final(const bend_blake2b_state* s, uint8_t* out);

// Diagnostics: Bend round trips so far, words of Bend heap in use.
uint64_t bend_blake2b_calls(void);
uint64_t bend_blake2b_heap_words(void);

#ifdef __cplusplus
}
#endif

#endif
