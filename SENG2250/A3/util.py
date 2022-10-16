# This script will serve as a module for all utilities needed by the client-server handshake
from random import randrange, getrandbits

# pip install pycryptodome
# One must avoid having both PyCrypto and PyCryptodome installed at the same time, as they will interfere with each other.

# If Nan says we can use this then just use the one below, otherwise use self implemented thingy
# import Crypto.Util.number as number

# Function for fast modular exponentiation
def fast_mod_exp(base, exponent, n):
    # If we mod by 1 the remainder is always 0 so return 0 if n is 1
    if n == 1:
        return 0

    rs = 1
    while exponent > 0:
        if exponent & 1 == 1:
            rs = (rs * base) % n

        # Shift bits to the right by 1 until we reach 0
        exponent = exponent >> 1
        base = (base * base) % n
    return rs


# The following functions will be used to generate prime numbers for RSA
def is_prime(n: int, k=128) -> bool:
    # Easy primes: 2, 3
    # All even numbers are not primes so we take care of them right away
    # Also get rid of negative numbers
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # Find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2

    # Test k times
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)

        if x != 1 and x != n - 1:
            j = 1

            while j < s and x != n - 1:

                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1

            if x != n - 1:
                return False
    return True


# Generate possible prime number
def generate_prime_candidate(length: int) -> int:
    # Generate random bits
    p = getrandbits(length)

    # LSR right by length - 1 times and or it with 1 to make sure the number is odd
    tempo = (1 << length - 1) | 1

    # Apply a mask to set MSB and LSB to 1
    p = p | tempo

    # p |= (1 << length - 1) | 1
    # p = p | (1 << length-1) | 1

    return p | tempo


# Keep generating prime candidates until it passes the is_prime() test
def generate_prime(length=1024) -> int:
    p = 4
    while is_prime(p, 128) is False:
        p = generate_prime_candidate(length)

    return p


# Functions for checking and finding modular inverses
def egcd(a: int, b: int) -> tuple:
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y


def find_mod_inv(a: int, m: int):
    g, x = egcd(a, m)
    return "The modular inverse of a and m is non existent" if g != 1 else x % m
