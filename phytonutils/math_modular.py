MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


def _extended_gcd_inverse(a, mod):
    """Returns the multiplicative inverse of a modulo mod (if it exists), else 0."""
    a %= mod
    x0, x1 = 1, 0
    m0, m1 = a, mod
    while m1:
        q = m0 // m1
        m0, m1 = m1, m0 - q * m1
        x0, x1 = x1, x0 - q * x1
    if m0 != 1:  # gcd != 1: no inverse
        return 0
    return x0 % mod


def modular_multiplicative_inverse(number, modulo):
    return _extended_gcd_inverse(number, modulo)


def modular_multiplicative_inverse_bits(number, bits):
    """Port of ModularMultiplicativeInverseBits.

    The Go code masks with (1<<bits)-1 (low bits) but arithmetic wraps at
    2^bits, so the inverse is taken modulo 2^bits.
    """
    return _extended_gcd_inverse(number & ((1 << bits) - 1), 1 << bits)


def modular_multiplicative_inverse_fixed(number):
    """Port of ModularMultiplicativeInverseFixed for a fixed-width integer type.

    Uses wrap-around arithmetic: the inverse is taken modulo 2^width, where
    width matches the Go type (32 or 64 bits).
    """
    bits = number.bit_length()
    width = 32 if bits <= 32 else 64
    mask = (1 << width) - 1
    return _extended_gcd_inverse(number & mask, 1 << width)
