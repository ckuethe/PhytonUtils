"""Port of github.com/icza/bitio.

Bit order: bits are packed into bytes from MSB (bit 7) to LSB (bit 0).
Multi-bit values are written/read LSB-first.
"""


class EOFError(Exception):
    pass


class BitWriter:
    def __init__(self):
        self._out = bytearray()
        self._buf = 0
        self._bits_in_byte = 0

    def write_bit(self, bit):
        if self._bits_in_byte == 8:
            self._out.append(self._buf)
            self._buf = 0
            self._bits_in_byte = 0
        self._buf |= (bit & 1) << (7 - self._bits_in_byte)
        self._bits_in_byte += 1

    def write_bool(self, value):
        self.write_bit(1 if value else 0)

    def write_bits(self, value, count):
        # Bits are written MSB-first within the value
        for i in range(count - 1, -1, -1):
            self.write_bit((value >> i) & 1)

    def close(self):
        if self._bits_in_byte != 0:
            self._out.append(self._buf)
            self._buf = 0
            self._bits_in_byte = 0

    def bytes(self):
        return bytes(self._out)


class BitReader:
    def __init__(self, data):
        self._data = data
        self._pos = 0
        self._buf = 0
        self._bits_in_byte = 0

    def read_bit(self):
        if self._bits_in_byte == 0:
            if self._pos >= len(self._data):
                raise EOFError()
            self._buf = self._data[self._pos]
            self._pos += 1
            self._bits_in_byte = 8
        bit = (self._buf >> 7) & 1
        self._buf <<= 1
        self._bits_in_byte -= 1
        return bit

    def read_bool(self):
        return self.read_bit() != 0

    def read_bits(self, count):
        value = 0
        for _ in range(count):
            value = (value << 1) | self.read_bit()
        return value
