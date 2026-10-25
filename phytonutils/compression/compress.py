from .constants import (
    DATA_MAX_SIZE,
    WINDOW_INITIAL_INDEX,
    OFFSET_BITS,
    LENGTH_BITS,
    LITERAL_BITS,
    MAX_UNCODED,
)
from .window import Window
from .bitio import BitWriter


def firmware_block_compress(data, exhaustive):
    if len(data) == 0:
        return bytes()

    if len(data) > DATA_MAX_SIZE:
        raise ValueError("out of bounds input")

    window_index = WINDOW_INITIAL_INDEX
    window = Window()

    writer = BitWriter()

    data = bytearray(data)
    while len(data) > 0:
        offset_index, length = window.find(window_index, data, exhaustive)

        if offset_index != -1:
            writer.write_bool(False)
            writer.write_bits(offset_index, OFFSET_BITS)
            writer.write_bits(length - MAX_UNCODED, LENGTH_BITS)
            window_index = window.set(window_index, data[:length])
            del data[:length]
        else:
            writer.write_bool(True)
            literal = data[0]
            del data[0]
            window_index = window.set_byte(window_index, literal)
            writer.write_bits(literal, LITERAL_BITS)

    writer.close()
    return writer.bytes()
