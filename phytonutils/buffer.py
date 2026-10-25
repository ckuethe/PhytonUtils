import struct


class EOFError(Exception):
    pass


class UnexpectedEOFError(Exception):
    pass


class Buffer:
    """A mutable byte buffer that supports sequential reads (port of buffer.Buffer)."""

    def __init__(self, data=bytes()):
        self._data = bytearray(data)

    def __len__(self):
        return len(self._data)

    def __getitem__(self, item):
        return self._data[item]

    def __setitem__(self, key, value):
        self._data[key] = value

    def _read_raw(self, n):
        """Internal read that returns (bytes, err). Returns at most n bytes."""
        if len(self._data) == 0:
            return bytes(), EOFError()
        if len(self._data) < n:
            result = bytes(self._data)
            self._data.clear()
            return result, UnexpectedEOFError()
        result = bytes(self._data[:n])
        del self._data[:n]
        return result, None

    def read_byte(self):
        data, err = self._read_raw(1)
        if err is not None:
            raise err
        return data[0]

    def read(self, n):
        return self._read_raw(n)

    def read_into(self, buf):
        """Reads into a bytearray buffer, returns error or None."""
        if len(self._data) == 0:
            return EOFError()
        if len(self._data) < len(buf):
            buf[:] = self._data
            self._data.clear()
            return UnexpectedEOFError()
        buf[:] = self._data[: len(buf)]
        del self._data[: len(buf)]
        return None

    def skip(self, n):
        if len(self._data) == 0:
            raise EOFError()
        if len(self._data) < n:
            raise UnexpectedEOFError()
        del self._data[:n]

    def read_int32(self):
        data, err = self._read_raw(4)
        if err is not None:
            raise err
        return struct.unpack("<i", data)[0]

    def read_uint32(self):
        data, err = self._read_raw(4)
        if err is not None:
            raise err
        return struct.unpack("<I", data)[0]

    def read_uint32_be(self):
        data, err = self._read_raw(4)
        if err is not None:
            raise err
        return struct.unpack(">I", data)[0]

    def read_float32(self):
        data, err = self._read_raw(4)
        if err is not None:
            raise err
        return struct.unpack("<f", data)[0]

    def read_int16(self):
        data, err = self._read_raw(2)
        if err is not None:
            raise err
        return struct.unpack("<h", data)[0]

    def read_uint16(self):
        data, err = self._read_raw(2)
        if err is not None:
            raise err
        return struct.unpack("<H", data)[0]

    def read_uint16_be(self):
        data, err = self._read_raw(2)
        if err is not None:
            raise err
        return struct.unpack(">H", data)[0]

    def read_bytes(self):
        n = self.read_byte()
        data, err = self._read_raw(n)
        if err is not None:
            raise err
        return data

    def read_string(self):
        return self.read_bytes().decode("latin-1")


class PanicBuffer(Buffer):
    """Port of buffer.PanicBuffer: non-erroring variants that panic (raise)."""

    def read_byte(self):
        return super().read_byte()

    def read(self, n):
        data, err = super().read(n)
        if err is not None:
            raise err
        return data

    def read_into(self, buf):
        err = super().read_into(buf)
        if err is not None:
            raise err
        return len(buf)

    def skip(self, n):
        super().skip(n)

    def read_int32(self):
        return super().read_int32()

    def read_uint32(self):
        return super().read_uint32()

    def read_uint32_be(self):
        return super().read_uint32_be()

    def read_float32(self):
        return super().read_float32()

    def read_int16(self):
        return super().read_int16()

    def read_uint16(self):
        return super().read_uint16()

    def read_uint16_be(self):
        return super().read_uint16_be()

    def read_bytes(self):
        return super().read_bytes()

    def read_string(self):
        return super().read_string()
