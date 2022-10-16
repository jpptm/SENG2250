from util import *


# This script will handle message encryption and decryption using RSA
class RSA:
    def __init__(self):

        # Generate rsa keys by using functions from the util module
        # Flag p and q as private members. They must not be touched from outside the class
        p = generate_prime(1024)
        q = generate_prime(1024)

        # RSA pub key
        self.e = 65537

        # n = pq
        self.n = p * q

        # Find phi_n
        phi_p = p - 1
        phi_q = q - 1
        phi_n = phi_p * phi_q

        # Find decryption key
        d = find_mod_inv(self.e, phi_n)
        self.public_key = (self.e, self.n)
        # Note that a real implementation should probably be written in a language that puts more emphasis on encapsulation
        self.__private_key = (p, q, d)

    # Functions for encrypting and decrypting a msg
    def encrypt(self, msg):
        return fast_mod_exp(msg, self.e, self.n)

    def decrypt(self, msg):
        return fast_mod_exp(msg, self.__private_key[2], self.n)

    """# Takse an int input to compute a signature
    def sign(self, msg):
        return fast_mod_exp(msg, self.__private_key[2], self.n)
"""
