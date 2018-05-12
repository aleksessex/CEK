import gmpy2, sys, math
from gmpy2 import mpz
from utils import crt
from prng import PRNG
from keypair import PublicKey, PrivateKey

def generate_CEK_prime(l, u, b, d):
    rs = PRNG()
    b_d = b ** d
    b_d_bits = int(math.ceil(math.log(b_d, 2)))
    if b == 2:
        p_t_bits = l - b_d_bits - u
        p_t = rs.random_prime(p_t_bits)
        while True:    
            p_s = rs.random_prime(u)
            p = b_d * p_s * p_t + 1
            if gmpy2.is_prime(p):
                return p_s, p
    else:
        p_t_bits = l - b_d_bits - u - 1
        p_t = rs.random_prime(p_t_bits)
        while True:    
            p_s = rs.random_prime(u)
            p = 2 * b_d * p_s * p_t + 1
            if gmpy2.is_prime(p):
                return p_s, p

def generate_h(p_s, p, q_s, q):
    """Compute a generator of a subgroup of Z^*_n that has order 
    p_s mod p and order q_s mod q"""
    rs = PRNG()
    while True:
        hp = gmpy2.powmod(rs.random_Zsp(p), mpz((p-1)/p_s), p)
        if hp != 1:
            break
    while True:
        hq = gmpy2.powmod(rs.random_Zsp(q), mpz((q-1)/q_s), q)
        if hq != 1:
            break
    return crt([p, q], [hp, hq])

def generate_g(b, d, p, q):
    """Compute a generator of a subgroup of Z^*_n that has order 
    b**d mod p and order b**d mod q"""
    rs = PRNG()
    b_to_the_d = b ** d
    while True:
        x = rs.random_Zsp(p)
        if gmpy2.powmod(x, mpz((p-1)/b), p) != 1:
            gp = gmpy2.powmod(x, mpz((p-1)/b_to_the_d), p)
            break
    while True:
        x = rs.random_Zsp(q)
        if gmpy2.powmod(x, mpz((q-1)/b), q) != 1:
            gq = gmpy2.powmod(x, mpz((q-1)/b_to_the_d), q)
            break
    return crt([p, q], [gp, gq])

def key_lengths(bits):
    """NIST Parameters for given security level
    https://www.keylength.com/en/4/"""
    if bits <= 112:
        l = 1024
        u = 224
    elif bits > 112 and bits <= 128:
        l = 1536
        u = 256
    elif bits > 128 and bits <= 192:
        l = 3840
        u = 384
    # Max defined security level
    elif bits >= 256:
        l = 7680
        u = 512
    return l,u


class Cryptosystem(object):

    def __init__(self):
        self.pub_key = None
        self.prv_key = None
        self.rs = PRNG()

    def load_key(self, pub_key_fn, prv_key_fn=None):     
        self.pub_key = PublicKey.load_from_file(pub_key_fn)
        if prv_key_fn is not None:
            self.prv_key = PrivateKey.load_from_file(prv_key_fn)

    def write_key(self, key_fn):      
        if self.pub_key is not None:
            self.pub_key.write_to_file(key_fn+".pub")
        if self.prv_key is not None:
            self.prv_key.write_to_file(key_fn+".prv")

    def generate_key(self, bits=112, b=2, d=256):
        if not gmpy2.is_prime(b):
            print "Base b must be prime"
            sys.exit()
        l,u = key_lengths(bits)
        if math.log(b**d, 2) > math.floor(l/4):
            print "b^d shall not exceed 1/4 the bit length of p or q"
            sys.exit()
        p_s, p = generate_CEK_prime(l, u, b, d)
        q_s, q = generate_CEK_prime(l, u, b, d)
        n = p * q
        h = generate_h(p_s, p, q_s, q)
        g = generate_g(b, d, p, q)
        p_s_inverse_mod_bd = gmpy2.invert(p_s, b ** d)
        x = p_s * p_s_inverse_mod_bd

        self.pub_key = PublicKey(n, g, h, b, d, u)
        self.prv_key = PrivateKey(x, p_s, p)

    # def ():
    #     self.g_log_bd = {}

    def encrypt(self, m):
        """Returns g^mh^r mod n"""
        if m >= self.pub_key.d:
            gm = 1
        elif m == 0:
            gm = self.pub_key.g
        else:
            gm = gmpy2.powmod(self.pub_key.g, self.pub_key.b ** m, self.pub_key.n)
        r = self.rs.random_bits_nz(self.pub_key.u)
        hr = gmpy2.powmod(self.pub_key.h, r, self.pub_key.n)
        return gmpy2.t_mod(gm * hr, self.pub_key.n)

    def rerandomize(self, c):
        return gmpy2.t_mod(c * self.encrypt(0), self.pub_key.n)

    def add(self, c, m):
        return gmpy2.powmod(c, self.pub_key.b ** m, self.pub_key.n)

    def decrypt(self, c):
        gm = gmpy2.powmod(c, self.prv_key.x, self.prv_key.p)
        if gm == 1:
            return "Inf"
        else:
            for m in xrange(0,self.pub_key.d):
                if gmpy2.powmod(self.pub_key.g, self.pub_key.b ** m, self.prv_key.p) == gm:
                    return m
        return "Decryption error"



