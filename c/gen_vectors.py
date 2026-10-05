#!/usr/bin/env python3
"""Write the vectors that check.c reads, one per line:
    name nn key salt personal msg digest      (hex; '-' for empty)
The digests are independent of this library: the BLAKE2 reference keyed
known-answer tests (tests/crypto/blake/blake2b/vectors/blake2b-kat.txt) and
Python's hashlib.blake2b(digest_size=, key=, salt=, person=).
usage: gen_vectors.py out.txt [count]"""
import hashlib
import os
import random
import struct
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'bend-collections'))


def kat():
    rows, cur = [], {}
    for line in open(os.path.join(ROOT, 'tests/crypto/blake/blake2b/vectors/blake2b-kat.txt')):
        line = line.strip()
        if line:
            k, v = line.split(':', 1)
            cur[k] = bytes.fromhex(v.strip())
            if k == 'hash':
                rows.append(cur)
                cur = {}
    return rows


def h(b):
    return b.hex() if b else '-'


def main():
    out = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
    rng = random.Random(0x7a63)
    rb = lambda n: bytes(rng.randrange(256) for _ in range(n))
    z16 = bytes(16)
    lines = []

    def row(name, nn, key, salt, person, msg, want=None):
        got = hashlib.blake2b(msg, digest_size=nn, key=key, salt=salt, person=person).digest()
        if want is not None:
            assert got == want, name
        lines.append(' '.join((name, str(nn), h(key), h(salt), h(person), h(msg), got.hex())))

    for i, r in enumerate(kat()):
        row('kat%d' % i, 64, r['key'], z16, z16, r['in'], r['hash'])
    nu5 = struct.pack('<I', 0xc2d6d0b4)
    zcash = [b'ZcashTxHash_' + nu5, b'ZTxIdHeadersHash', b'ZTxIdTranspaHash', b'ZTxAuthHash_' + nu5,
             b'ZTxIdSaplingHash', b'ZTxIdOrchardHash', b'ZcashPoW' + struct.pack('<II', 200, 9),
             b'ZcashPoW' + struct.pack('<II', 144, 5), b'Zcash_ExpandSeed', b'ZcashIP32Sapling',
             b'Zcash_RedJubjubH', b'ZcashBlockCommit', b'ZcashHistory' + nu5, b'ZcashTxHash_' + bytes(4)]
    # Equihash 200,9 as the equihash crate feeds it: header (140) + nonce, then a 4-byte index
    for i in range(16):
        row('equihash200_9_%d' % i, 50, b'', z16, zcash[6], rb(140) + struct.pack('<I', i))
    for i in range(count):
        nn = rng.choice([1, 20, 31, 32, 33, 48, 50, 63, 64, rng.randrange(1, 65)])
        kk = rng.choice([0, 0, 0, 1, 16, 32, 63, 64, rng.randrange(0, 65)])
        ll = rng.choice([0, 1, 4, 127, 128, 129, 140, 144, 255, 256, 257, 1024, rng.randrange(0, 600),
                         rng.randrange(0, 5000)])
        salt = rng.choice([z16, rb(16)])
        person = rng.choice([z16, rb(16), rng.choice(zcash)])
        row('rand%d' % i, nn, rb(kk), salt, person, rb(ll))
    for ll in (65536, 1 << 20):
        row('long%d' % ll, 64, b'', z16, z16, rb(ll))
        row('long%d_keyed' % ll, 32, rb(32), rb(16), zcash[0], rb(ll))
    with open(out, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    print('wrote', len(lines), 'vectors to', out)


if __name__ == '__main__':
    main()
