class OuterMangleKeyOffset:
    DEFAULT = 0
    FLASH = 0
    DEVICE_ID = 1
    MEMORY = 6


class KeyMaterial:
    def __init__(
        self,
        generator=None,
        outer_key_offset=OuterMangleKeyOffset.DEFAULT,
        device_key=None,
        alternate_key_table=None,
        crc=None,
    ):
        self.generator = generator
        self.outer_key_offset = outer_key_offset
        self.device_key = device_key
        self.alternate_key_table = alternate_key_table
        self.crc = crc


def new_flash_key_material(generator):
    return KeyMaterial(
        generator=generator,
        outer_key_offset=OuterMangleKeyOffset.FLASH,
        device_key=None,
        alternate_key_table=None,
    )


def new_memory_key_material(generator):
    return KeyMaterial(
        generator=generator,
        outer_key_offset=OuterMangleKeyOffset.MEMORY,
        device_key=None,
        alternate_key_table=None,
    )
