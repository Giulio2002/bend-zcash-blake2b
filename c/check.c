// Checks libbendblake2b against the vectors of gen_vectors.py (hashlib and the
// BLAKE2 reference KAT): the one-shot call, and the incremental API fed whole,
// in fixed and random pieces, and through a copied (forked) state.
//   cc -O2 check.c -L<out> -lbendblake2b -lpthread -lm -o check && ./check vectors.txt
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bend_blake2b.h"

static size_t unhex(const char* s, uint8_t** out) {
  if (strcmp(s, "-") == 0) {
    *out = NULL;
    return 0;
  }
  size_t n = strlen(s) / 2;
  *out = malloc(n ? n : 1);
  for (size_t i = 0; i < n; i++) {
    sscanf(s + 2 * i, "%2hhx", &(*out)[i]);
  }
  return n;
}

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next(void) {
  rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
  return rng;
}

// The incremental hash with pieces of `step` bytes (0: random 0..300).
static int incremental(const uint8_t* key, size_t kk, const uint8_t* salt, const uint8_t* person,
                       size_t nn, const uint8_t* msg, size_t ll, size_t step, uint8_t* out) {
  bend_blake2b_state s;
  int r = bend_blake2b_init(&s, key, kk, salt, person, nn);
  for (size_t i = 0; r == 0 && i < ll;) {
    size_t n = step ? step : (size_t)(next() % 301);
    if (n > ll - i) {
      n = ll - i;
    }
    r = bend_blake2b_update(&s, msg + i, n);
    i += n;
  }
  return r ? r : bend_blake2b_final(&s, out);
}

int main(int argc, char** argv) {
  FILE* f = fopen(argc > 1 ? argv[1] : "vectors.txt", "r");
  if (!f) {
    perror("vectors");
    return 2;
  }
  static char line[1 << 23];
  char name[64], nns[8], *tok[5];
  long rows = 0, checks = 0, fails = 0;
  while (fgets(line, sizeof line, f)) {
    char* p = strtok(line, " \n");
    if (!p) {
      continue;
    }
    snprintf(name, sizeof name, "%s", p);
    snprintf(nns, sizeof nns, "%s", strtok(NULL, " \n"));
    for (int i = 0; i < 5; i++) {
      tok[i] = strtok(NULL, " \n");
    }
    uint8_t *key, *salt, *person, *msg, *want;
    size_t nn = (size_t)atoi(nns);
    size_t kk = unhex(tok[0], &key);
    unhex(tok[1], &salt);
    unhex(tok[2], &person);
    size_t ll = unhex(tok[3], &msg);
    unhex(tok[4], &want);
    uint8_t got[64];
    rows++;
    size_t steps[] = {(size_t)-1, 1, 7, 128, 129, 0, 0};
    int ways = ll > 70000 ? 3 : 7;   // long messages: one-shot, whole, 128s... skip byte-wise
    for (int w = 0; w < ways; w++) {
      if (ll > 70000 && w == 1) {
        continue;
      }
      int r;
      memset(got, 0xee, sizeof got);
      if (w == 0) {
        r = bend_blake2b(key, kk, salt, person, nn, msg, ll, got);
      } else {
        size_t st = steps[w] == (size_t)-1 ? (ll ? ll : 1) : steps[w];
        r = incremental(key, kk, salt, person, nn, msg, ll, st, got);
      }
      checks++;
      if (r != 0 || memcmp(got, want, nn) != 0) {
        fails++;
        if (fails < 20) {
          printf("FAIL %s way %d r=%d nn=%zu kk=%zu ll=%zu\n", name, w, r, nn, kk, ll);
        }
      }
    }
    // a forked state: hash a prefix, copy, finish both halves differently
    if (ll >= 2 && ll < 70000) {
      bend_blake2b_state a, b;
      uint8_t g1[64];
      bend_blake2b_init(&a, key, kk, salt, person, nn);
      bend_blake2b_update(&a, msg, ll / 2);
      b = a;
      bend_blake2b_update(&b, msg + 1, 1);       // diverge the copy
      bend_blake2b_update(&a, msg + ll / 2, ll - ll / 2);
      bend_blake2b_final(&a, g1);
      checks++;
      if (memcmp(g1, want, nn) != 0) {
        fails++;
        printf("FAIL %s fork\n", name);
      }
    }
    free(key); free(salt); free(person); free(msg); free(want);
  }
  // invalid parameters are rejected
  uint8_t o[64], k[65] = {0};
  bend_blake2b_state s;
  int bad[] = {
    bend_blake2b(NULL, 0, NULL, NULL, 0, NULL, 0, o),
    bend_blake2b(NULL, 0, NULL, NULL, 65, NULL, 0, o),
    bend_blake2b(k, 65, NULL, NULL, 32, NULL, 0, o),
    bend_blake2b_init(&s, NULL, 0, NULL, NULL, 0),
    bend_blake2b_init(&s, k, 65, NULL, NULL, 32),
  };
  for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    checks++;
    if (bad[i] != -1) {
      fails++;
      printf("FAIL invalid case %u returned %d\n", i, bad[i]);
    }
  }
  printf("vectors %ld checks %ld failures %ld bend calls %llu heap words %llu\n", rows, checks, fails,
         (unsigned long long)bend_blake2b_calls(), (unsigned long long)bend_blake2b_heap_words());
  return fails != 0;
}
