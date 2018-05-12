import os, gmpy2
from gmpy2 import mpz


class Random(object):

    def __init__(self):
        try:
            a = os.urandom(32)
            self.rs = gmpy2.random_state(int(a.encode('hex'), 16))
        except:
            print "Problem initializing PRNG"
            sys.exit()
    
    def random_n(self, n):
        """Returns random number in range 0..n-1"""
        return gmpy2.mpz_random(self.rs, n)

    def random_Zsp(self, p):
        """Returns random element in range 2...p-2"""
        while True:
            r = gmpy2.mpz_random(self.rs, p)
            if r >= 2 and r < p-1:
                return r

    def random_bits(self, b):
        """Returns a random number in the range 0..2^b-1"""
        return gmpy2.mpz_urandomb(self.rs, b)

    def random_prime(self, b):
        """Returns a random b-bit prime"""
        while True:
            p = self.random_bits(b)
            if gmpy2.is_prime(p):
                return p