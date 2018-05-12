import gmpy2, math, os
from gmpy2 import mpz

def crt(n, x):
    """Chinese remainder. For n = [n1, n2, ...] and x = [x1, x2, ...]
    computes an r such that:
    r \equiv x1 mod n1
    r \equiv x2 mod n2, etc."""
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, x_i in zip(n, x):
        p = prod / n_i
        sum += x_i * gmpy2.invert(p, n_i) * p
    return gmpy2.t_mod(sum, prod)