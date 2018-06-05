import json, sys
import gmpy2, math
from gmpy2 import mpz


class PublicKey(object):
    """
    n: pq where p, q, are l-bit primes such that:
        if b = 2:
            p = 2^d * p_s * p_t + 1
            q = 2^d * q_s * q_t + 1
        Otherwise: 
            p = 2 * b^d * p_s * p_t
            q = 2 * b^d * q_s * q_t
    g: Generator of message space of b^d mod p, and order b^d mod q.
    h: Generator of randomizer space of order p_s mod p, and q_s mod q.
    b: Small prime base
    d: Threshold bound
    u: Bitlength of randomizer space in Z^*_p and Z^*_q
    """
    def __init__(self, n, g, h, b, d, u):

        if not (gmpy2.powmod(g, mpz(b ** d), n) == 1):
            """Do basic validation"""
            print "Generator g does not have order b^d"
            sys.exit()

        self.n = n
        self.g = g
        self.h = h
        self.b = b
        self.d = d
        self.u = u

    def __repr__(self):
        return "{'n': " + str(self.n) + ", 'g': " + str(self.g) + ", 'h': " + \
        str(self.h) + ", 'b': " + str(self.b) + ", 'd': " + str(self.d) + \
        ", 'u': " + str(self.u) + "}"

    @classmethod
    def load_from_file(cls, filename):
        """Load public key from file"""
        try:
            with open(filename, 'r') as infile:
                key_obj = json.load(infile)
        except:
            print "Public key file could not be read"
            sys.exit()

        try:    
            n = mpz(key_obj['n'])
            g = mpz(key_obj['g'])
            h = mpz(key_obj['h'])
            b = int(key_obj['b'])
            d = int(key_obj['d'])
            u = int(key_obj['u'])
            return cls(n, g, h, b, d, u)
        except:
            print "Public key parameters missing"
            sys.exit()    

    def write_to_file(self, filename):
        
        pub_key = {'n': str(self.n), 'g': str(self.g), 'h': str(self.h), 'b': \
        str(self.b), 'd': str(self.d), 'u': str(self.u)}

        try:
            with open(filename, 'w') as outfile:
                json.dump(pub_key, outfile)
        except:
            print "Could not write public key to file"


class PrivateKey(object):
    """
    p:   One of the prime factors of n of the form described above
    p_s: Order of h mod p
    x:   Multiplicative inverse of p_s mod b^d
    """
    def __init__(self, x, p_s, p):

        if not (gmpy2.is_prime(p)):
            """Do basic validation"""
            print "p not prime"
            sys.exit()

        if not (gmpy2.is_prime(p_s)):
            print "p_s not prime"
            sys.exit()

        self.x = x
        self.p_s = p_s
        self.p = p

    def __repr__(self):
        return "{'x': " + str(self.x) + ", 'p_s': " + str(self.p_s) + \
        ", 'p': " + str(self.p) + "}"        

    @classmethod
    def load_from_file(cls, filename):
        """Load private key from file"""
        try:
            with open(filename, 'r') as infile:
                key_obj = json.load(infile)
        except:
            print "Private key file could not be read"
            sys.exit()

        try:
            x = mpz(key_obj['x'])
            p_s = mpz(key_obj['p_s'])
            p = mpz(key_obj['p'])
            return cls(x, p_s, p)

        except:
            print "Private key parameters missing"
            sys.exit()

    def write_to_file(self, filename):
        
        prv_key = {'x': str(self.x), 'p_s': str(self.p_s), 'p': str(self.p)}                    

        try:
            with open(filename, 'w') as outfile:
                json.dump(prv_key, outfile)
        except:
            print "Could not write private key to file"