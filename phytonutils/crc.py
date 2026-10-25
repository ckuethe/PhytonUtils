import struct

POLYNOMIAL = 0x04C11DB7
INITIAL_VALUE = 0xFFFFFFFF
MASK32 = 0xFFFFFFFF


def _polynomial_division(polynomial, input_, bits):
    mask = (1 << bits) - 1
    for _ in range(bits):
        bit_out = (input_ >> (bits - 1)) > 0
        input_ <<= 1
        if bit_out:
            input_ ^= polynomial
        input_ &= mask
    return input_


def _build_table(polynomial):
    table = [0] * 256
    for i in range(256):
        table[i] = _polynomial_division(polynomial, i, 32) & MASK32
    return table


TABLE = _build_table(POLYNOMIAL)


class CRC:
    def __init__(self):
        self._crc = INITIAL_VALUE

    def update(self, buf):
        chunk_size = 4
        remainder = len(buf) % chunk_size
        chunks = len(buf) // chunk_size

        for chunks_left in range(chunks, 0, -1):
            index = (chunks - chunks_left) * chunk_size
            value = struct.unpack_from("<I", buf, index)[0]
            self.update_uint32(value)

        if remainder != 0:
            padding = buf[chunks * chunk_size:]
            self.update(padding)

    def update_uint32(self, data):
        crc = self._crc & MASK32

        crc = TABLE[(data >> 24) & 0xFF ^ (crc >> 24) & 0xFF] ^ (crc << 8)
        crc = TABLE[(data >> 16) & 0xFF ^ (crc >> 24) & 0xFF] ^ (crc << 8)
        crc = TABLE[(data >> 8) & 0xFF ^ (crc >> 24) & 0xFF] ^ (crc << 8)
        crc = TABLE[data & 0xFF ^ (crc >> 24) & 0xFF] ^ (crc << 8)

        self._crc = crc & MASK32

    def sum32(self):
        return self._crc & MASK32


def calculate_crc(buf):
    crc = CRC()
    crc.update(buf)
    return crc.sum32()
