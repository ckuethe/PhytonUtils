from .constants import (
    DATA_MAX_SIZE,
    WINDOW_INITIAL_INDEX,
    OFFSET_BITS,
    LENGTH_BITS,
    LITERAL_BITS,
    MAX_UNCODED,
)
from .window import Window
from .bitio import BitReader, EOFError


class OutOfBoundsOutputError(Exception):
    pass


def firmware_block_decompress(data):
    window_index = WINDOW_INITIAL_INDEX
    output = bytearray()
    window = Window()
    window_buffer = bytearray(len(window._t))

    reader = BitReader(data)

    try:
        while True:
            is_literal = reader.read_bool()

            if not is_literal:
                offset_index = reader.read_bits(OFFSET_BITS)
                length = reader.read_bits(LENGTH_BITS) + MAX_UNCODED
                if DATA_MAX_SIZE < (length + len(output)):
                    raise OutOfBoundsOutputError("out of bounds output")

                window_index, buf = window.getset(
                    offset_index, window_index, length, window_buffer
                )
                output.extend(buf)
            else:
                literal = reader.read_bits(LITERAL_BITS)
                if (DATA_MAX_SIZE - 1) < len(output):
                    raise OutOfBoundsOutputError("out of bounds output")

                output.append(literal)
                window_index = window.set_byte(window_index, literal)
    except EOFError:
        pass

    return bytes(output)
