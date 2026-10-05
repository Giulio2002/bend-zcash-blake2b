#!/usr/bin/env python3
"""Equihash solutions verified with the Bend BLAKE2b (personalization "ZcashPoW" + n + k).

Reads the test vectors of the equihash crate (librustzcash
components/equihash/src/test_vectors/{valid,invalid}.rs: (n, k) = (96, 5),
(144, 5) and (200, 9), Zcash's parameters) and runs the crate's verifier
(verify.rs: Node::new, tree_validator, expand_array), transcribed here, with
the Bend BLAKE2b in the incremental way the crate uses it: one state over
input + nonce, cloned for every 4-byte index. Every valid solution must
verify, every invalid one must fail with the crate's error kind, and a
solution with one index changed must fail.
usage: check_equihash.py <libbendblake2b.so> <valid.rs> <invalid.rs>"""
import ast
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bendblake2b  # noqa: E402


def rust_vectors(path):
    """The TestVector { params, input, nonce, solution(s), error } literals of a .rs file."""
    src = open(path).read()
    out = []
    for block in re.split(r'TestVector \{', src)[1:]:
        m = re.search(r'params: Params \{ n: (\d+), k: (\d+)', block)
        if not m:
            continue   # the struct definition
        n, k = map(int, m.groups())
        inp = re.search(r'input: b"((?:[^"\\]|\\.)*)"', block).group(1)
        inp = ast.literal_eval('b"%s"' % inp)
        m = re.search(r'nonce: \[0; 32\]', block)
        nonce = bytes(32) if m else bytes(int(x, 0) for x in re.search(r'nonce: \[([^\]]*)\]', block).group(1).replace(',', ' ').split())
        body = block[block.index('solution'):].split('TestVector')[0]
        body = body[body.index(':') + 1:]
        err = re.search(r'error: Kind::(\w+)', block)
        if err:
            body = body[:body.index('error')]
        lists = [[int(x, 0) for x in re.findall(r'0x[0-9a-fA-F]+|\d+', l)] for l in re.findall(r'\[([0-9a-fA-Fx,\s]+)\]', body)]
        out.append({'n': n, 'k': k, 'input': inp, 'nonce': nonce, 'solutions': lists,
                    'error': err.group(1) if err else None})
    return out


class Invalid(Exception):
    pass


def expand_array(vin, bit_len, byte_pad=0):
    out_width = (bit_len + 7) // 8 + byte_pad
    out_len = 8 * out_width * len(vin) // bit_len
    if out_len == len(vin):
        return bytes(vin)
    vout = bytearray(out_len)
    mask = (1 << bit_len) - 1
    acc_bits = acc = j = 0
    for b in vin:
        acc = ((acc << 8) | b) & 0xffffffff
        acc_bits += 8
        if acc_bits >= bit_len:
            acc_bits -= bit_len
            for x in range(byte_pad, out_width):
                vout[j + x] = (acc >> (acc_bits + 8 * (out_width - x - 1))) & ((mask >> (8 * (out_width - x - 1))) & 0xff)
            j += out_width
    return bytes(vout)


def verify(blake, n, k, inp, nonce, indices):
    per = 512 // n
    cbits = n // (k + 1)
    cbytes = (cbits + 7) // 8
    state = blake(digest_size=per * n // 8, person=b'ZcashPoW' + struct.pack('<II', n, k))
    state.update(inp)
    state.update(nonce)

    def leaf(i):
        s = state.copy()
        s.update(struct.pack('<I', i // per))
        h = s.digest()
        start = (i % per) * n // 8
        return (expand_array(h[start:start + n // 8], cbits), [i])

    def tree(ix):
        if len(ix) == 1:
            return leaf(ix[0])
        mid = len(ix) // 2
        a, b = tree(ix[:mid]), tree(ix[mid:])
        if a[0][:cbytes] != b[0][:cbytes]:
            raise Invalid('Collision')
        if b[1][0] < a[1][0]:
            raise Invalid('OutOfOrder')
        if set(a[1]) & set(b[1]):
            raise Invalid('DuplicateIdxs')
        h = bytes(x ^ y for x, y in zip(a[0], b[0]))[cbytes:]
        return (h, a[1] + b[1] if a[1][0] < b[1][0] else b[1] + a[1])

    root = tree(list(indices))
    if any(root[0][:cbytes]):
        raise Invalid('NonZeroRootHash')


def outcome(blake, v, sol):
    try:
        verify(blake, v['n'], v['k'], v['input'], v['nonce'], sol)
        return 'ok'
    except Invalid as e:
        return str(e)


def main():
    bendblake2b.load(sys.argv[1])
    import hashlib
    valid, invalid = rust_vectors(sys.argv[2]), rust_vectors(sys.argv[3])
    checks = fails = 0
    by = {}
    for v in valid:
        for sol in v['solutions']:
            assert len(sol) == 1 << v['k'], (v['n'], v['k'], len(sol))
            # the transcribed verifier with hashlib accepts it (control)
            assert outcome(hashlib.blake2b, v, sol) == 'ok'
            got = outcome(bendblake2b.blake2b, v, sol)
            checks += 1
            key = '(%d,%d)' % (v['n'], v['k'])
            by[key] = by.get(key, 0) + 1
            if got != 'ok':
                fails += 1
                print('FAIL valid (%d,%d) solution rejected: %s' % (v['n'], v['k'], got))
            bad = list(sol)
            bad[len(bad) // 3] ^= 1
            checks += 1
            if outcome(bendblake2b.blake2b, v, bad) == 'ok':
                fails += 1
                print('FAIL mutated (%d,%d) solution accepted' % (v['n'], v['k']))
    for v in invalid:
        for sol in v['solutions']:
            checks += 1
            got = outcome(bendblake2b.blake2b, v, sol)
            if got != v['error']:
                fails += 1
                print('FAIL invalid (%d,%d): %s, want %s' % (v['n'], v['k'], got, v['error']))
    print('equihash: valid solutions by (n,k) %s, %d invalid vectors, %d checks, %d failures, %d Bend ZcashPoW digests' % (
        by, sum(len(v['solutions']) for v in invalid), checks, fails, sum(c for p, c in bendblake2b.CALLS.items() if p.startswith(b'ZcashPoW'))))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
