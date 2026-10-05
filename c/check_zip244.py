#!/usr/bin/env python3
"""The ZIP-244 test vectors (txid, auth digest, every sighash) computed with the Bend BLAKE2b.

Runs the reference generator of zcash-test-vectors (zcash_test_vectors/zip_0244.py,
which builds ten NU5 transactions from a fixed seed and hashes them) with
hashlib.blake2b replaced by libbendblake2b, and compares its output with the
published test-vectors/json/zip_0244.json byte for byte.
usage: check_zip244.py <libbendblake2b.so> <zcash-test-vectors checkout>"""
import contextlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bendblake2b  # noqa: E402


def main():
    lib, ztv = sys.argv[1], os.path.abspath(sys.argv[2])
    bendblake2b.load(lib)
    bendblake2b.install()          # before the reference code binds `from hashlib import blake2b`
    sys.path.insert(0, ztv)
    from zcash_test_vectors import zip_0244
    assert zip_0244.blake2b is bendblake2b.blake2b, 'the reference code does not use the Bend BLAKE2b'
    sys.argv = ['zip_0244', '-t', 'json']
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        zip_0244.main()
    got = json.loads(buf.getvalue())
    want = json.load(open(os.path.join(ztv, 'test-vectors/json/zip_0244.json')))
    fields = want[1][0].split(', ')
    fails = 0
    for i, (g, w) in enumerate(zip(got[2:], want[2:])):
        for f, a, b in zip(fields, g, w):
            if a != b:
                fails += 1
                print('FAIL vector %d %s' % (i, f))
    n = sum(1 for w in want[2:] for f, v in zip(fields, w) if f in ('txid', 'auth_digest') or f.startswith('sighash') and v)
    print('zip244: %d transactions, %d digests (txid, auth_digest, sighashes) compared, %d failures' % (
        len(want) - 2, n, fails + (len(got) != len(want))))
    print('bend BLAKE2b digests by personalization:')
    for p, c in sorted(bendblake2b.CALLS.items()):
        label = ''.join(chr(b) if 32 < b < 127 else '\\x%02x' % b for b in p) or '(none)'
        print('  %-34s %d' % (label, c))
    return 1 if fails or len(got) != len(want) else 0


if __name__ == '__main__':
    sys.exit(main())
