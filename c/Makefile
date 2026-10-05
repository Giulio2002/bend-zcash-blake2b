# libbendblake2b: the proved Bend BLAKE2b (../bend-collections) as a C library.
#
#   make                 libbendblake2b.a and libbendblake2b.so in $(OUT) from the
#                        checked-in bendblake2b.c (no Bend needed)
#   make regen BEND=...  regenerate bendblake2b.c with Bend 2.0.34 from entry.bend
#   make check           the C harness on hashlib + BLAKE2 KAT vectors
#   make check-zcash ZTV=<zcash-test-vectors> EQ=<librustzcash equihash test_vectors dir>
#   make bench           throughput against libsodium (needs libsodium.so.23)
CC     ?= clang
OUT    ?= build
BEND   ?= $(HOME)/.bend/v2.0.34/bend/bin/bend
CFLAGS ?= -O3
LIBS    = -lpthread -lm

all: $(OUT)/libbendblake2b.a $(OUT)/libbendblake2b.so

$(OUT)/bendblake2b.o: bendblake2b.c blake2b_ffi.c bend_blake2b.h
	@mkdir -p $(OUT)
	$(CC) -std=c11 $(CFLAGS) -c -fPIC -fvisibility=hidden -I. -Dmain=bendblake2b_unused_main $< -o $@

$(OUT)/libbendblake2b.a: $(OUT)/bendblake2b.o
	rm -f $@ && ar rcs $@ $<

$(OUT)/libbendblake2b.so: $(OUT)/bendblake2b.o
	$(CC) -shared -o $@ $< $(LIBS)

# Bend splices blake2b_ffi.c into the C it generates from entry.bend.
regen:
	BEND_NO_TELEMETRY=1 $(BEND) entry.bend -o bendblake2b.c

$(OUT)/check: check.c $(OUT)/libbendblake2b.a
	$(CC) -O2 -I. $< -L$(OUT) -l:libbendblake2b.a $(LIBS) -o $@

$(OUT)/vectors.txt: gen_vectors.py
	@mkdir -p $(OUT)
	python3 gen_vectors.py $@

check: $(OUT)/check $(OUT)/vectors.txt
	$(OUT)/check $(OUT)/vectors.txt

check-zcash: $(OUT)/libbendblake2b.so
	python3 check_zip244.py $(OUT)/libbendblake2b.so $(ZTV)
	python3 check_equihash.py $(OUT)/libbendblake2b.so $(EQ)/valid.rs $(EQ)/invalid.rs

$(OUT)/bench: bench.c $(OUT)/libbendblake2b.a
	$(CC) -O2 -I. $< -L$(OUT) -l:libbendblake2b.a -l:libsodium.so.23 $(LIBS) -o $@

bench: $(OUT)/bench
	$(OUT)/bench 2

clean:
	rm -rf $(OUT)

.PHONY: all regen check check-zcash bench clean
