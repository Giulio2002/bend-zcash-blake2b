// Throughput of libbendblake2b against libsodium's BLAKE2b (crypto_generichash).
//   cc -O2 bench.c -L<out> -l:libbendblake2b.a -l:libsodium.so.23 -lpthread -lm -o bench
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "bend_blake2b.h"

// libsodium's prototypes (the runtime library is enough; no -dev headers needed).
int sodium_init(void);
int crypto_generichash_blake2b_salt_personal(unsigned char* out, size_t outlen, const unsigned char* in,
                                             unsigned long long inlen, const unsigned char* key,
                                             size_t keylen, const unsigned char* salt,
                                             const unsigned char* personal);

static double now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec * 1e-9;
}

static const uint8_t personal[16] = "ZcashTxHash_\xb4\xd0\xd6\xc2";
static const uint8_t salt[16] = {0};

typedef int (*hashfn)(const uint8_t*, size_t, uint8_t*);

static int bend_one(const uint8_t* m, size_t n, uint8_t* o) {
  return bend_blake2b(NULL, 0, salt, personal, 32, m, n, o);
}
static int bend_inc(const uint8_t* m, size_t n, uint8_t* o) {
  bend_blake2b_state s;
  bend_blake2b_init(&s, NULL, 0, salt, personal, 32);
  bend_blake2b_update(&s, m, n);
  return bend_blake2b_final(&s, o);
}
static int sodium(const uint8_t* m, size_t n, uint8_t* o) {
  return crypto_generichash_blake2b_salt_personal(o, 32, m, n, NULL, 0, salt, personal);
}

static void run(const char* name, hashfn f, const uint8_t* m, size_t n, double secs) {
  uint8_t o[64];
  long it = 0;
  double t0 = now(), t;
  do {
    for (int i = 0; i < 8; i++) {
      f(m, n, o);
    }
    it += 8;
    t = now() - t0;
  } while (t < secs);
  printf("%-16s %8zu B  %10.2f MB/s  %10.2f us/hash\n", name, n, it * (double)n / t / 1e6, t / it * 1e6);
}

int main(int argc, char** argv) {
  double secs = argc > 1 ? atof(argv[1]) : 2.0;
  sodium_init();
  size_t sizes[] = {144, 1024, 1 << 20};
  uint8_t* m = malloc(1 << 20);
  for (size_t i = 0; i < (1u << 20); i++) {
    m[i] = (uint8_t)(i * 131 + 7);
  }
  uint8_t a[32], b[32];
  bend_one(m, 1000, a);
  sodium(m, 1000, b);
  if (memcmp(a, b, 32)) {
    printf("MISMATCH\n");
    return 1;
  }
  for (int s = 0; s < 3; s++) {
    run("bend one-shot", bend_one, m, sizes[s], secs);
    run("bend incremental", bend_inc, m, sizes[s], secs);
    run("libsodium", sodium, m, sizes[s], secs);
  }
  return 0;
}
