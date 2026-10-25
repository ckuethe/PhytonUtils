"""Port of firmware/firmware.go."""

import struct

from .. import buffer as buffer_mod
from ..compression.compress import firmware_block_compress
from ..compression.decompress import firmware_block_decompress
from .. import crc as crc_mod
from ..encryption.block import new_encrypted_block, EncryptedBlock
from ..encryption.material import new_flash_key_material
from .keys import BLOCK_HEADER_SIZE_KEY, BLOCK_HEADER_ADDR_KEY
from .time import DateTime

SERIAL_NUMBER_SIZE = 16
MARKER_SIZE = 8
MARKER_PHYTON = b"Phyton\x00\x00"
MARKER_ALMACODE = b"AlmaCode"

BASE_ADDRESS = 0x8000000


def _zero_terminated_slice(data):
    try:
        idx = data.index(0)
    except ValueError:
        return data
    return data[:idx]


class ASFirmwareHeader:
    def __init__(self):
        self.description = bytes(256)
        self.date_time = DateTime()
        self.data_size = 0

    def description_string(self):
        try:
            return _zero_terminated_slice(self.description).decode("cp1251")
        except Exception:
            return ""


class ASFileHeader:
    def __init__(self):
        self.marker = bytes(MARKER_SIZE)
        self.header_size = 0
        self.date_time = DateTime()
        self.buffer_size = 0
        self.serial_number = bytes(SERIAL_NUMBER_SIZE)
        self.version_low = 0
        self.version_high = 0
        self.file_count = 0
        self.firmware_header_size = 0
        self.compressed = 0
        self.reserved = 0
        self.crc32 = 0
        self.update_crc32 = 0

    def is_alma_code(self):
        return self.marker == MARKER_ALMACODE


class ASBlockHeader:
    def __init__(self):
        self.header_size = 0
        self.size = 0
        self.addr = 0
        self.size_aligned = 0


class Block:
    def __init__(self, header=None, block=None):
        self.header = header if header is not None else ASBlockHeader()
        self.block = block if block is not None else EncryptedBlock()


class Entry:
    def __init__(self):
        self.header = ASFirmwareHeader()
        self.blocks = []
        self._compressed = False

    def code(self):
        """Port of Entry.Code: reconstructs the firmware image bytes."""
        buf = bytearray()
        for b in self.blocks:
            dec_block = EncryptedBlock(b.block.bytes())
            dec_block.decrypt(new_flash_key_material(None), not self._compressed)

            if self._compressed:
                data = firmware_block_decompress(bytes(dec_block.data_block()[: b.header.size]))
                calculated_crc = crc_mod.calculate_crc(data)
                crc1, _ = dec_block.crc()
                if calculated_crc != crc1:
                    raise ValueError("wrong CRC")

                new_length = b.header.addr - BASE_ADDRESS + len(data)
                if len(buf) < new_length:
                    buf.extend(bytearray(new_length - len(buf)))
                start = b.header.addr - BASE_ADDRESS
                buf[start : start + len(data)] = data
            else:
                new_length = b.header.addr - BASE_ADDRESS + len(dec_block.data_block())
                if len(buf) < new_length:
                    buf.extend(bytearray(new_length - len(buf)))
                buf[b.header.addr - BASE_ADDRESS :] = dec_block.data_block()

        return bytes(buf)


class Firmware:
    def __init__(self, data=b""):
        self.file_header = ASFileHeader()
        self.entries = []
        self.data = data

    def length(self):
        if self.file_header.is_alma_code():
            raise NotImplementedError("not implemented")
        return len(self.data) - self.file_header.header_size


def blocks_from_data(data):
    input_data = buffer_mod.PanicBuffer(data)
    result = []
    while len(input_data) > 0:
        block_header = ASBlockHeader()
        block_header.header_size = input_data.read_uint32()
        block_header.size = input_data.read_uint32() ^ BLOCK_HEADER_SIZE_KEY
        block_header.addr = input_data.read_uint32() ^ BLOCK_HEADER_ADDR_KEY
        block_header.size_aligned = block_header.size
        if (block_header.size_aligned % 8) != 0:
            block_header.size_aligned = (block_header.size_aligned & 0xFFFFFFF8) + 8

        encrypted_block = new_encrypted_block(int(block_header.size_aligned))
        input_data.read_into(encrypted_block._data)

        result.append(Block(header=block_header, block=encrypted_block))

    return result


def load_firmware(buf):
    """Port of firmware.LoadFirmware."""
    fw = Firmware(data=bytearray(buf))

    data_buf = buffer_mod.Buffer(buf)
    marker, err = data_buf.read(MARKER_SIZE)
    if err is not None:
        raise err
    fw.file_header.marker = marker

    is_alma_code = marker == MARKER_ALMACODE

    if not is_alma_code and marker != MARKER_PHYTON:
        raise ValueError("unsupported header")

    fw.file_header.header_size = data_buf.read_uint32()
    data_buf = buffer_mod.Buffer(buf[12 : fw.file_header.header_size])

    date_time = data_buf.read_uint32()
    fw.file_header.date_time = DateTime(date_time)
    fw.file_header.buffer_size = data_buf.read_uint32()
    serial, err = data_buf.read(SERIAL_NUMBER_SIZE)
    if err is not None:
        raise err
    fw.file_header.serial_number = serial

    try:
        fw.file_header.version_low = data_buf.read_byte()
        fw.file_header.version_high = data_buf.read_byte()
        fw.file_header.file_count = data_buf.read_uint32()
        fw.file_header.firmware_header_size = data_buf.read_uint32()
        fw.file_header.compressed = data_buf.read_byte()
        fw.file_header.reserved = data_buf.read_byte()
        fw.file_header.crc32 = data_buf.read_uint32()
    except buffer_mod.EOFError:
        pass

    if fw.file_header.is_alma_code():
        for file_n in range(fw.file_header.file_count):
            offset = fw.file_header.header_size + fw.file_header.firmware_header_size * file_n
            file_buffer = buffer_mod.Buffer(
                buf[
                    offset : offset + fw.file_header.firmware_header_size
                ]
            )
            entry = Entry()
            desc, err = file_buffer.read(256)
            if err is not None:
                raise err
            entry.header.description = desc
            date_time = file_buffer.read_uint32()
            entry.header.date_time = DateTime(date_time)
            entry.header.data_size = file_buffer.read_uint32()
            entry._compressed = fw.file_header.compressed > 0
            fw.entries.append(entry)

        offset = fw.file_header.header_size + fw.file_header.firmware_header_size * fw.file_header.file_count
        for i, entry in enumerate(fw.entries):
            fw.entries[i].blocks = blocks_from_data(
                buf[offset : offset + entry.header.data_size]
            )
            offset += entry.header.data_size

        if offset != len(fw.data):
            raise ValueError("data lingering after read")
    else:
        entry = Entry()
        entry.header.date_time = fw.file_header.date_time
        entry.header.data_size = len(fw.data[fw.file_header.header_size :])
        entry.blocks = blocks_from_data(fw.data[fw.file_header.header_size :])
        entry._compressed = fw.file_header.compressed > 0
        fw.entries.append(entry)

    fw.file_header.update_crc32 = crc_mod.calculate_crc(fw.data)

    return fw
