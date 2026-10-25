"""Port of firmware/flash.go."""

import struct

from .. import buffer as buffer_mod
from ..encryption import borlandrand as br

FLASH_AREA_PUBLIC_SIGNATURE = 0x19601217


class FlashAreaData:
    def __init__(self, public_signature=0, struct_len=0, data=b""):
        self.public_signature = public_signature
        self.struct_len = struct_len
        self.data = data


class FlashAreaDataPublicAPI:
    def __init__(self):
        self.boot_signature = 0
        self.product_serial_number = bytes(32)
        self.target_file_name = bytes(32)
        self.product_name = bytes(64)
        self.calibration_bp0 = 0
        self.calibration_bp290 = 0
        self.vendor_id = 0
        self.product_id = 0
        self.manufacturer_name = bytes(32)
        self.target_id = 0
        self.target_start_timeout = 0


class FlashArea:
    UNKNOWN = 0
    PUBLIC_API = 1


class FlashStatus:
    OK = 0
    INV_ADDR = 1
    WR_PROT = 2
    NOT_BLANK = 3
    VERIFY = 4
    ERASE = 5
    PROG = 6
    INIT_ER = 7
    SIGN_ER = 8
    INVALID_CRC = 9
    INVALID_KEY_NUMB = 10
    INVALID_SIGN = 11
    INVALID_AREA_NAME = 12
    INVALID_TARGET = 13
    RDP_ERR = 14


class InvalidFlashAreaError(Exception):
    pass


class InvalidSignatureError(Exception):
    pass


class InvalidFlashStatusError(Exception):
    pass


class UnexpectedEofError(Exception):
    pass


def decode_read_flash_area(data):
    """Port of firmware.DecodeReadFlashArea."""
    buf = buffer_mod.Buffer(data)

    flash_status_int = buf.read_uint32()

    if flash_status_int != FlashStatus.OK:
        if flash_status_int == FlashStatus.INVALID_AREA_NAME:
            raise InvalidFlashAreaError("area out of bounds")
        elif flash_status_int == FlashStatus.INVALID_SIGN:
            raise InvalidSignatureError("invalid area public signature")
        raise InvalidFlashStatusError("invalid flash status %d" % flash_status_int)

    # random seed is set by device using register TIM6_CNT at 0x40001024
    random_seed = buf.read_uint32()

    size = buf.read_uint32()

    size, random_seed = br.borland_rand_xor_uint32(size, random_seed)
    if size > len(buf):
        raise UnexpectedEofError("unexpected end of data")

    flash_data_bytes, err = buf.read(size)
    if err is not None:
        raise err

    random_seed = br.borland_rand_xor_in_place(flash_data_bytes, random_seed)

    flash_data = buffer_mod.Buffer(flash_data_bytes)

    area_data = FlashAreaData()
    area_data.public_signature = flash_data.read_uint32()
    area_data.struct_len = flash_data.read_uint32()
    if area_data.struct_len != (len(flash_data) + 8):
        raise UnexpectedEofError("unexpected end of data")

    area_data.data = bytes(flash_data._data)

    return area_data
