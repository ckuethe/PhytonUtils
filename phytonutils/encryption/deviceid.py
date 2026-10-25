import struct

from .keys import HARDCODED_MANGLE_TABLE, MangleKeyData
from .material import OuterMangleKeyOffset
from . import rounds

MASK32 = 0xFFFFFFFF


class DeviceId:
    """Port of encryption.DeviceId ([3]uint32)."""

    def __init__(self, values=(0, 0, 0)):
        self.v0 = values[0] & MASK32
        self.v1 = values[1] & MASK32
        self.v2 = values[2] & MASK32


def device_mangle_key_offset6(device_id):
    outer_key = HARDCODED_MANGLE_TABLE[OuterMangleKeyOffset.DEVICE_ID]
    d = bytearray(16)
    struct.pack_into("<I", d, 0, device_id.v0 ^ _round_key(outer_key, 0))
    struct.pack_into("<I", d, 4, device_id.v1 ^ _round_key(outer_key, 1))
    struct.pack_into("<I", d, 8, device_id.v2 ^ _round_key(outer_key, 2))
    struct.pack_into("<I", d, 12, _round_key(outer_key, 3))
    return MangleKeyData(d)


def device_mangle_key_offset0(device_id):
    outer_key = HARDCODED_MANGLE_TABLE[OuterMangleKeyOffset.DEFAULT]
    d = bytearray(16)
    struct.pack_into("<I", d, 0, device_id.v0 ^ _round_key(outer_key, 0))
    struct.pack_into("<I", d, 4, device_id.v1 ^ _round_key(outer_key, 1))
    struct.pack_into("<I", d, 8, device_id.v2 ^ _round_key(outer_key, 2))
    struct.pack_into("<I", d, 12, (~device_id.v0) & MASK32 ^ _round_key(outer_key, 3))
    return MangleKeyData(d)


def _round_key(data, round_):
    return struct.unpack_from("<I", data, (round_ & 3) << 2)[0]


def decrypt_device_code(device_id, code):
    if len(code) % 8 != 0:
        raise ValueError("len must be % 8")
    key = device_mangle_key_offset0(device_id)
    rounds.decrypt_data(key, code)
    return code


def encrypt_device_code(device_id, code):
    if len(code) % 8 != 0:
        raise ValueError("len must be % 8")
    key = device_mangle_key_offset0(device_id)
    rounds.encrypt_data(key, code)
    return code
