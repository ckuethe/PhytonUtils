import struct

from .borlandrand import (
    borland_rand,
    borland_rand_previous_seed,
    borland_rand_output,
    BORLAND_RAND_OUTPUT_SHIFT,
    BORLAND_RAND_OUTPUT_MASK,
)
from .block import (
    EncryptedBlock,
    ENCRYPTED_BLOCK_KEY_SIZE,
    ENCRYPTED_BLOCK_MANGLE_KEY_OFFSET,
    ENCRYPTED_BLOCK_CRC1_OFFSET,
    ENCRYPTED_BLOCK_PADDING_KEY_OFFSET,
)

MASK32 = 0xFFFFFFFF


def _ones_count32(value):
    return bin(value & MASK32).count("1")


def is_key_borland_seed_likely(b, material):
    """Port of encryption.IsKeyBorlandSeedLikely."""
    data = EncryptedBlock(b.bytes())
    try:
        data.decrypt(material, False)
    except Exception:
        return False

    key_block = data.key_block()
    for i in range(ENCRYPTED_BLOCK_MANGLE_KEY_OFFSET, ENCRYPTED_BLOCK_CRC1_OFFSET, 2):
        if struct.unpack_from("<H", key_block, i)[0] & 0x8000:
            return False

    for i in range(ENCRYPTED_BLOCK_PADDING_KEY_OFFSET, ENCRYPTED_BLOCK_KEY_SIZE, 2):
        if struct.unpack_from("<H", key_block, i)[0] & 0x8000:
            return False

    return True


def bruteforce_borland_seed(b, material):
    if not is_key_borland_seed_likely(b, material):
        raise ValueError("not a borland rand seed")

    data = EncryptedBlock(b.bytes())
    data.decrypt(material, False)

    data_size = 2
    state_data_start = ENCRYPTED_BLOCK_MANGLE_KEY_OFFSET
    state_data_end = ENCRYPTED_BLOCK_CRC1_OFFSET - data_size
    valid_state_bits = _ones_count32(BORLAND_RAND_OUTPUT_MASK)
    valid_state_inverse_bits = _ones_count32(~BORLAND_RAND_OUTPUT_MASK & MASK32)
    state_output_mask = (BORLAND_RAND_OUTPUT_MASK << BORLAND_RAND_OUTPUT_SHIFT) & MASK32

    key_block = data.key_block()

    def get_possible_states(state, previous_output):
        states = []
        limit = 1 << valid_state_inverse_bits
        for n in range(limit):
            seed = (
                (state & state_output_mask)
                | ((n & (MASK32 ^ 0xFFFF)) << valid_state_bits)
                | (n & 0xFFFF)
            ) & MASK32
            prev_seed = borland_rand_previous_seed(seed)
            if borland_rand_output(prev_seed) == previous_output:
                states.append(prev_seed)
        return states

    possible_states = []

    state_index = state_data_end
    previous_output = struct.unpack_from("<H", key_block, state_index - data_size)[0]
    previous_state = (
        (struct.unpack_from("<H", key_block, state_index)[0] << BORLAND_RAND_OUTPUT_SHIFT)
        & state_output_mask
    )
    states = get_possible_states(previous_state, previous_output)
    next_states = sorted(set(states))
    possible_states = next_states

    state_index -= data_size

    # Last rounds backwards with checks
    while state_index >= state_data_start:
        for j in range(len(possible_states) - 1, -1, -1):
            prev_state = borland_rand_previous_seed(possible_states[j])
            _, output = borland_rand(prev_state)
            if output != struct.unpack_from("<H", key_block, state_index)[0]:
                del possible_states[j]
                continue
            possible_states[j] = prev_state
        state_index -= data_size

    possible_states = sorted(set(possible_states))

    return possible_states


def bruteforce_borland_seed_bytes(b, material):
    data = EncryptedBlock(b.bytes())
    data.decrypt(material, False)

    data_size = 1
    state_data_start = ENCRYPTED_BLOCK_MANGLE_KEY_OFFSET
    state_data_end = ENCRYPTED_BLOCK_CRC1_OFFSET - data_size
    byte_output_mask = BORLAND_RAND_OUTPUT_MASK & 0xFF
    valid_state_bits = _ones_count32(byte_output_mask)
    valid_state_inverse_bits = _ones_count32(~byte_output_mask & MASK32)
    state_output_mask = (byte_output_mask << BORLAND_RAND_OUTPUT_SHIFT) & MASK32

    key_block = data.key_block()

    def get_possible_states(state, previous_output):
        states = []
        limit = 1 << valid_state_inverse_bits
        for n in range(limit):
            seed = (
                (state & state_output_mask)
                | ((n & (MASK32 ^ 0xFFFF)) << valid_state_bits)
                | (n & 0xFFFF)
            ) & MASK32
            prev_seed = borland_rand_previous_seed(seed)
            if (borland_rand_output(prev_seed) & 0xFF) == previous_output:
                states.append(prev_seed)
        return states

    possible_states = []

    state_index = state_data_end
    previous_output = key_block[state_index - data_size]
    previous_state = (
        (key_block[state_index] << BORLAND_RAND_OUTPUT_SHIFT) & state_output_mask
    )
    states = get_possible_states(previous_state, previous_output)
    next_states = sorted(set(states))
    possible_states = next_states

    state_index -= data_size

    # Last rounds backwards with checks
    while state_index >= state_data_start:
        for j in range(len(possible_states) - 1, -1, -1):
            prev_state = borland_rand_previous_seed(possible_states[j])
            _, output = borland_rand(prev_state)
            if (output & 0xFF) != key_block[state_index]:
                del possible_states[j]
                continue
            possible_states[j] = prev_state
        state_index -= data_size

    possible_states = sorted(set(possible_states))

    return possible_states
