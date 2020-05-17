
from base64 import b64decode
from math import ceil, log
from decimal import *

from Crypto.Util.number import getPrime

def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def gcd(a, b):
    while b != 0:
        a, b = b, a % b

    return a


def lcm(a, b):
    return a // gcd(a, b) * b


def mod_inv(a, n):
    t, r = 0, n
    new_t, new_r = 1, a

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise Exception("a is not invertible")
    if t < 0:
        t = t + n

    return t

class RSA:

    def __init__(self, key_length):
        self.e = 3
        phi = 0

        while gcd(self.e, phi) != 1:
            p, q = getPrime(key_length // 2), getPrime(key_length // 2)
            phi = lcm(p - 1, q - 1)
            self.n = p * q

        self._d = mod_inv(self.e, phi)

    def encrypt(self, binary_data):
        int_data = int.from_bytes(binary_data, byteorder='big')
        return pow(int_data, self.e, self.n)

    def decrypt(self, encrypted_int_data):
        int_data = pow(encrypted_int_data, self._d, self.n)
        return int_to_bytes(int_data)



class RSAParityOracle(RSA):

    def is_parity_odd(self, encrypted_int_data):
        return pow(encrypted_int_data, self._d, self.n) & 1


def parity_oracle_attack(ciphertext, rsa_parity_oracle, holliwood=False):

    multiplier = pow(2, rsa_parity_oracle.e, rsa_parity_oracle.n)

    lower_bound = Decimal(0)
    upper_bound = Decimal(rsa_parity_oracle.n)

    k = int(ceil(log(rsa_parity_oracle.n, 2)))

    getcontext().prec = k

    for _ in range(k):
        ciphertext = (ciphertext * multiplier) % rsa_parity_oracle.n

        if rsa_parity_oracle.is_parity_odd(ciphertext):
            lower_bound = (lower_bound + upper_bound) / 2
        else:
            upper_bound = (lower_bound + upper_bound) / 2

        if holliwood is True:
            print(int_to_bytes(int(upper_bound)))

    return int_to_bytes(int(upper_bound))


def main():
    input_bytes = b64decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IG"
                            "Fyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")

    rsa_parity_oracle = RSAParityOracle(1024)

    ciphertext = rsa_parity_oracle.encrypt(input_bytes)
    rsa_parity_oracle.decrypt(ciphertext)

    plaintext = parity_oracle_attack(ciphertext, rsa_parity_oracle)
    assert plaintext == input_bytes


if __name__ == '__main__':
    main()