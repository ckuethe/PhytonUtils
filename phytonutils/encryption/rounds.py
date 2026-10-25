import struct

from .keys import MANGLED_KEY_BLOCK_SIZE, MANGLED_KEY_ROUNDS

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


def _encrypt_round(round_key, data_a, data_b, round_):
    return (
        (round_ + round_key + ((data_b >> 8) ^ (data_b << 6)) + data_b + data_a) & MASK32,
        data_b,
    )


def _decrypt_round(round_key, data_a, data_b, round_):
    return (
        ((data_a - data_b) - ((data_b >> 8) ^ (data_b << 6)) - round_key - round_) & MASK32,
        data_b,
    )


def encrypt_block(key, block):
    """Port of MangleKeyData.EncryptBlock."""
    data_a = block & MASK32
    data_b = (block >> 32) & MASK32

    for round_ in range(MANGLED_KEY_ROUNDS):
        round_key = key.round_key(round_)
        data_b, data_a = _encrypt_round(round_key, data_a, data_b, round_)

    return data_a | (data_b << 32)


def decrypt_block(key, block):
    """Port of MangleKeyData.DecryptBlock."""
    data_a = block & MASK32
    data_b = (block >> 32) & MASK32

    for round_ in range(MANGLED_KEY_ROUNDS - 1, -1, -1):
        round_key = key.round_key(round_)
        data_a, data_b = _decrypt_round(round_key, data_b, data_a, round_)

    return data_a | (data_b << 32)


def encrypt_data(key, data):
    """In-place encryption of a bytearray, processing 8-byte blocks."""
    for i in range(0, len(data), MANGLED_KEY_BLOCK_SIZE):
        block = struct.unpack_from("<Q", data, i)[0]
        enc = encrypt_block(key, block)
        struct.pack_into("<Q", data, i, enc & MASK64)


def decrypt_data(key, data):
    """In-place decryption of a bytearray, processing 8-byte blocks."""
    for i in range(0, len(data), MANGLED_KEY_BLOCK_SIZE):
        block = struct.unpack_from("<Q", data, i)[0]
        dec = decrypt_block(key, block)
        struct.pack_into("<Q", data, i, dec & MASK64)
