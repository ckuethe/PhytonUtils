MASK48 = (1 << 48) - 1

JAVA_RAND_MULTIPLIER = 0x5DEECE66D  # 25214903917
JAVA_RAND_ADDEND = 11
JAVA_RAND_OUTPUT_SHIFT = 48 - 16
JAVA_RAND_OUTPUT_MASK = 0xFFFF
JAVA_RAND_MODULUS = (1 << 48) - 1
# Calculated using math.ModularMultiplicativeInverseBits(uint64(JavaRandMultiplier), 48)
JAVA_RAND_MULTIPLIER_INVERSE = 0xDFE05BCB1365


def java_rand_next_seed(seed):
    return (seed * JAVA_RAND_MULTIPLIER + JAVA_RAND_ADDEND) & MASK48


def java_rand_output(seed):
    return (seed >> JAVA_RAND_OUTPUT_SHIFT) & JAVA_RAND_OUTPUT_MASK


def java_rand_output_bits(seed, bits):
    return seed >> (48 - bits)


def java_rand_previous_seed(seed):
    return ((seed - JAVA_RAND_ADDEND) * JAVA_RAND_MULTIPLIER_INVERSE) & MASK48


def java_rand(seed):
    new_seed = java_rand_next_seed(seed)
    return new_seed, java_rand_output(new_seed)
