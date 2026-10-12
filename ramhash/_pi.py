"""Round constants: consecutive 64-bit words of the binary expansion of
frac(pi) (nothing up my sleeve: anyone can recompute them)."""

MAX_ROUNDS = 64
NWORDS = MAX_ROUNDS * 8


def _arctan_inv(x, one):
    total = term = one // x
    x2, n, sign = x * x, 3, -1
    while term:
        term //= x2
        total += sign * (term // n)
        n += 2
        sign = -sign
    return total


def pi_fraction_words(nwords=NWORDS):
    bits = 64 * nwords
    one = 1 << (bits + 64)  # 64 guard bits
    pi = 16 * _arctan_inv(5, one) - 4 * _arctan_inv(239, one)  # Machin
    frac = (pi >> 64) - (3 << bits)
    return [(frac >> (bits - 64 * (i + 1))) & (2**64 - 1) for i in range(nwords)]
