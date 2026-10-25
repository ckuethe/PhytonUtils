import struct

from .keys import HARDCODED_MANGLE_TABLE, ALTERNATE_MANGLE_TABLE, MangleKeyData
from .material import OuterMangleKeyOffset
from . import rounds
from .. import crc as crc_mod

ENCRYPTED_BLOCK_KEY_SIZE = 512

ENCRYPTED_BLOCK_MANGLE_INDEX_OFFSET = 0
ENCRYPTED_BLOCK_MANGLE_KEY_OFFSET = ENCRYPTED_BLOCK_MANGLE_INDEX_OFFSET + 2
ENCRYPTED_BLOCK_CRC1_OFFSET = ENCRYPTED_BLOCK_MANGLE_KEY_OFFSET + 16
ENCRYPTED_BLOCK_CRC2_OFFSET = ENCRYPTED_BLOCK_CRC1_OFFSET + 4
ENCRYPTED_BLOCK_PADDING_KEY_OFFSET = ENCRYPTED_BLOCK_CRC2_OFFSET + 4

# Mangle index constants
MANGLED_INDEX_NORMAL_KEY0 = 0
MANGLED_INDEX_NORMAL_KEY1 = 1
MANGLED_INDEX_NORMAL_KEY2 = 2
MANGLED_INDEX_NORMAL_KEY3 = 3
MANGLED_INDEX_NORMAL_KEY4 = 4
MANGLED_INDEX_NORMAL_KEY5 = 5
MANGLED_INDEX_NORMAL_KEY6 = 6
MANGLED_INDEX_NORMAL_KEY7 = 7

MANGLED_INDEX_ALTERNATE_KEY0 = 8
MANGLED_INDEX_ALTERNATE_KEY1 = 9
MANGLED_INDEX_ALTERNATE_KEY2 = 10
MANGLED_INDEX_ALTERNATE_KEY3 = 11
MANGLED_INDEX_ALTERNATE_KEY4 = 12
MANGLED_INDEX_ALTERNATE_KEY5 = 13
MANGLED_INDEX_ALTERNATE_KEY6 = 14
MANGLED_INDEX_ALTERNATE_KEY7 = 15

MANGLED_INDEX_DEVICE_KEY = 0xFFFF


class InvalidKeyError(Exception):
    pass


class UnsupportedDeviceKeyError(Exception):
    pass


class CrcMismatchError(Exception):
    pass


class InvalidCrcPairError(Exception):
    pass


class EncryptedBlock:
    """Port of encryption.EncryptedBlock: an in-place mutable block."""

    def __init__(self, data=None):
        if data is None:
            data = bytes(ENCRYPTED_BLOCK_KEY_SIZE)
        self._data = bytearray(data)

    def __len__(self):
        return len(self._data)

    def __getitem__(self, item):
        return self._data[item]

    def __setitem__(self, key, value):
        self._data[key] = value

    def bytes(self):
        return bytes(self._data)

    def mangle_key(self):
        return memoryview(self._data)[
            ENCRYPTED_BLOCK_MANGLE_KEY_OFFSET:ENCRYPTED_BLOCK_CRC1_OFFSET
        ]

    def mangle_key_block(self):
        return memoryview(self._data)[
            ENCRYPTED_BLOCK_MANGLE_KEY_OFFSET:ENCRYPTED_BLOCK_PADDING_KEY_OFFSET
        ]

    def key_block(self):
        return memoryview(self._data)[:ENCRYPTED_BLOCK_KEY_SIZE]

    def data_block(self):
        return memoryview(self._data)[ENCRYPTED_BLOCK_KEY_SIZE:]

    def mangle_index(self):
        return struct.unpack_from("<H", self._data, ENCRYPTED_BLOCK_MANGLE_INDEX_OFFSET)[0]

    def crc(self):
        crc1 = struct.unpack_from("<I", self._data, ENCRYPTED_BLOCK_CRC1_OFFSET)[0]
        crc2 = struct.unpack_from("<I", self._data, ENCRYPTED_BLOCK_CRC2_OFFSET)[0]
        return crc1, crc2

    def reset(self):
        for i in range(len(self._data)):
            self._data[i] = 0

    def _generate_key_block(self, material):
        if material.crc is not None:
            crc_value = material.crc(self.data_block())
        else:
            crc_value = crc_mod.calculate_crc(self.data_block())

        struct.pack_into("<I", self._data, ENCRYPTED_BLOCK_CRC1_OFFSET, crc_value)
        struct.pack_into("<I", self._data, ENCRYPTED_BLOCK_CRC2_OFFSET, crc_value)

        material.generator.fill_key_block(
            memoryview(self._data)[ENCRYPTED_BLOCK_MANGLE_KEY_OFFSET:ENCRYPTED_BLOCK_CRC1_OFFSET]
        )
        material.generator.fill_key_block(
            memoryview(self._data)[ENCRYPTED_BLOCK_PADDING_KEY_OFFSET:ENCRYPTED_BLOCK_KEY_SIZE]
        )

        return material.generator.mangle_index()

    def _select_key(self, mangle_index, material):
        if mangle_index <= MANGLED_INDEX_NORMAL_KEY7:
            return MangleKeyData(HARDCODED_MANGLE_TABLE[mangle_index])
        elif mangle_index <= MANGLED_INDEX_ALTERNATE_KEY7:
            if material.alternate_key_table is None:
                return MangleKeyData(
                    ALTERNATE_MANGLE_TABLE[mangle_index - MANGLED_INDEX_ALTERNATE_KEY0]
                )
            return MangleKeyData(material.alternate_key_table[mangle_index - MANGLED_INDEX_ALTERNATE_KEY0])
        else:
            if mangle_index != MANGLED_INDEX_DEVICE_KEY:
                raise InvalidKeyError("invalid key number")
            if material.device_key is None:
                raise UnsupportedDeviceKeyError("unsupported device key")
            return MangleKeyData(material.device_key)

    def encrypt(self, material):
        mangle_index = self._generate_key_block(material)

        # Mangle of data
        rounds.encrypt_data(MangleKeyData(self.mangle_key()), self.data_block())

        # Inner mangle of key
        key_data = self._select_key(mangle_index, material)
        rounds.encrypt_data(key_data, self.mangle_key_block())

        struct.pack_into("<H", self._data, ENCRYPTED_BLOCK_MANGLE_INDEX_OFFSET, mangle_index)

        # Outer mangle of key
        outer_key = MangleKeyData(HARDCODED_MANGLE_TABLE[material.outer_key_offset])
        rounds.encrypt_data(outer_key, self.key_block())

    def decrypt(self, material, verify_crc):
        # Outer unmangle of key
        outer_key = MangleKeyData(HARDCODED_MANGLE_TABLE[material.outer_key_offset])
        rounds.decrypt_data(outer_key, self.key_block())

        mangle_index = self.mangle_index()

        key_data = self._select_key(mangle_index, material)

        # Inner unmangle of key + CRC data
        rounds.decrypt_data(key_data, self.mangle_key_block())

        # Unmangle of data
        rounds.decrypt_data(MangleKeyData(self.mangle_key()), self.data_block())

        crc1, crc2 = self.crc()
        if crc1 != crc2:
            raise InvalidCrcPairError("invalid CRC pair")

        if verify_crc:
            if material.crc is not None:
                calculated_crc = material.crc(self.data_block())
            else:
                calculated_crc = crc_mod.calculate_crc(self.data_block())
            if calculated_crc != crc1:
                raise CrcMismatchError(
                    "data CRC not matching: expected %08x, got %08x"
                    % (crc1, calculated_crc)
                )

    def __repr__(self):
        return "EncryptedBlock(%d bytes)" % len(self._data)


# Mangle methods are provided via rounds.encrypt_data / rounds.decrypt_data.


def new_encrypted_block(size):
    if size % 8 != 0:
        raise ValueError("size must be % 8")
    return EncryptedBlock(bytes(ENCRYPTED_BLOCK_KEY_SIZE + size))
