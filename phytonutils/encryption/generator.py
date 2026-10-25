import os
import struct

from .borlandrand import (
    borland_rand,
    BORLAND_RAND_MULTIPLIER_INVERSE,
    BORLAND_RAND_MODULUS,
)
from . import keys as keys_mod
from .keys import MangleKeyData

MASK32 = 0xFFFFFFFF


class KeyGenerator:
    def fill_key_block(self, data):
        raise NotImplementedError

    def mangle_index(self):
        raise NotImplementedError


class SecureRandomKeyGenerator(KeyGenerator):
    def fill_key_block(self, data):
        for i in range(len(data)):
            data[i] = os.urandom(1)[0]

    def mangle_index(self):
        return os.urandom(1)[0] & 0x7


class BorlandRandKeyGenerator(KeyGenerator):
    def __init__(self, seed):
        self._seed = seed & MASK32

    def fill_key_block(self, data):
        seed = self._seed
        for i in range(0, len(data), 2):
            seed, output = borland_rand(seed)
            struct.pack_into("<H", data, i, output)
        self._seed = seed

    def mangle_index(self):
        seed = self._seed
        seed, output = borland_rand(seed)
        self._seed = seed
        return output & 0x7


class BorlandRandByteKeyGenerator(KeyGenerator):
    def __init__(self, seed):
        self._seed = seed & MASK32

    def fill_key_block(self, data):
        seed = self._seed
        for i in range(len(data)):
            seed, output = borland_rand(seed)
            data[i] = output & 0xFF
        self._seed = seed

    def mangle_index(self):
        seed = self._seed
        seed, output = borland_rand(seed)
        self._seed = seed
        return output & 0x7


class ZeroKeyGenerator(KeyGenerator):
    def fill_key_block(self, data):
        for i in range(len(data)):
            data[i] = 0

    def mangle_index(self):
        return 0


class MangleIndexGeneratorWrapper(KeyGenerator):
    def __init__(self, generator, mangle_index):
        self._generator = generator
        self._mangle_index = mangle_index

    def fill_key_block(self, data):
        self._generator.fill_key_block(data)

    def mangle_index(self):
        return self._mangle_index


class MangleIndexOffsetGeneratorWrapper(KeyGenerator):
    def __init__(self, generator, offset):
        self._generator = generator
        self._offset = offset

    def fill_key_block(self, data):
        self._generator.fill_key_block(data)

    def mangle_index(self):
        return self._generator.mangle_index() + self._offset
