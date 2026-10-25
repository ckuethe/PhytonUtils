import struct

MASK32 = 0xFFFFFFFF

BORLAND_RAND_MULTIPLIER = 0x015A4E35  # 22695477
BORLAND_RAND_ADDEND = 1
BORLAND_RAND_OUTPUT_SHIFT = 16
BORLAND_RAND_OUTPUT_MASK = 0x7FFF
BORLAND_RAND_MODULUS = 0xFFFFFFFF
# Calculated using math.ModularMultiplicativeInverseFixed(uint32(BorlandRandMultiplier))
BORLAND_RAND_MULTIPLIER_INVERSE = 0x2925141D


def borland_rand_next_seed(seed):
    return (seed * BORLAND_RAND_MULTIPLIER + BORLAND_RAND_ADDEND) & MASK32


def borland_rand_output(seed):
    return (seed >> BORLAND_RAND_OUTPUT_SHIFT) & BORLAND_RAND_OUTPUT_MASK


def borland_rand_previous_seed(seed):
    return ((seed - BORLAND_RAND_ADDEND) * BORLAND_RAND_MULTIPLIER_INVERSE) & MASK32


def borland_rand(seed):
    new_seed = borland_rand_next_seed(seed)
    return new_seed, borland_rand_output(new_seed)


def borland_rand_xor_bytes(src, dst, seed):
    """XORs src into dst using the BorlandRand stream; returns new seed."""
    dst = bytearray(dst)
    for i in range(len(src)):
        seed, output = borland_rand(seed)
        dst[i] = src[i] ^ (output & 0xFF)
    return seed, bytes(dst)


def borland_rand_xor_in_place(data, seed):
    """XORs data in place; returns new seed."""
    return borland_rand_xor_bytes(data, data, seed)[0]


def borland_rand_xor_uint32(value, seed):
    """Port of BorlandRandXORUint32: returns (new_value, new_seed)."""
    buf = struct.pack("<I", value & MASK32)
    new_seed, new_buf = borland_rand_xor_bytes(buf, buf, seed)
    return struct.unpack("<I", new_buf)[0], new_seed
