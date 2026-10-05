"""hashlib.blake2b's interface over libbendblake2b (ctypes), for the checks.

    import bendblake2b; bendblake2b.load('/path/libbendblake2b.so')
    bendblake2b.install()        # hashlib.blake2b is now the Bend BLAKE2b
"""
import collections
import ctypes
import hashlib

_lib = None
CALLS = collections.Counter()   # digests computed, by personalization


class _State(ctypes.Structure):
    _fields_ = [('h', ctypes.c_uint64 * 8), ('t', ctypes.c_uint64 * 2), ('buf', ctypes.c_uint8 * 128),
                ('buflen', ctypes.c_uint32), ('outlen', ctypes.c_uint32)]


def load(path):
    global _lib
    _lib = ctypes.CDLL(path)
    _lib.bend_blake2b_init.argtypes = [ctypes.POINTER(_State), ctypes.c_char_p, ctypes.c_size_t,
                                       ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    _lib.bend_blake2b_update.argtypes = [ctypes.POINTER(_State), ctypes.c_char_p, ctypes.c_size_t]
    _lib.bend_blake2b_final.argtypes = [ctypes.POINTER(_State), ctypes.c_char_p]
    _lib.bend_blake2b.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p,
                                  ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    _lib.bend_blake2b_calls.restype = ctypes.c_uint64
    return _lib


def _pad16(b):
    b = bytes(b)
    if len(b) > 16:
        raise ValueError('salt/person longer than 16 bytes')
    return b + bytes(16 - len(b))


class blake2b:
    """The subset of hashlib.blake2b the Zcash reference code uses (sequential mode)."""
    name = 'blake2b'
    block_size = 128

    def __init__(self, data=b'', *, digest_size=64, key=b'', salt=b'', person=b'', fanout=1, depth=1,
                 leaf_size=0, node_offset=0, node_depth=0, inner_size=0, last_node=False, usedforsecurity=True):
        if (fanout, depth, leaf_size, node_offset, node_depth, inner_size, last_node) != (1, 1, 0, 0, 0, 0, False):
            raise ValueError('only sequential mode')
        self.digest_size = digest_size
        self._person = bytes(person)
        self._s = _State()
        key = bytes(key)
        r = _lib.bend_blake2b_init(ctypes.byref(self._s), key, len(key), _pad16(salt), _pad16(person), digest_size)
        if r:
            raise ValueError('bend_blake2b_init: %d' % r)
        if data:
            self.update(data)

    def update(self, data):
        data = bytes(data)
        r = _lib.bend_blake2b_update(ctypes.byref(self._s), data, len(data))
        if r:
            raise RuntimeError('bend_blake2b_update: %d' % r)

    def copy(self):
        c = blake2b.__new__(blake2b)
        c.digest_size, c._person, c._s = self.digest_size, self._person, _State()
        ctypes.memmove(ctypes.byref(c._s), ctypes.byref(self._s), ctypes.sizeof(_State))
        return c

    def digest(self):
        out = ctypes.create_string_buffer(self.digest_size)
        r = _lib.bend_blake2b_final(ctypes.byref(self._s), out)
        if r:
            raise RuntimeError('bend_blake2b_final: %d' % r)
        CALLS[self._person] += 1
        return out.raw

    def hexdigest(self):
        return self.digest().hex()


def oneshot(msg, digest_size=64, key=b'', salt=b'', person=b''):
    out = ctypes.create_string_buffer(digest_size)
    key = bytes(key)
    r = _lib.bend_blake2b(key, len(key), _pad16(salt), _pad16(person), digest_size, bytes(msg), len(msg), out)
    if r:
        raise ValueError('bend_blake2b: %d' % r)
    return out.raw


def install():
    hashlib.blake2b = blake2b
