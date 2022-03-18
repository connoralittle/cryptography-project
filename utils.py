from Crypto.Util.number import size, getPrime, isPrime
from sympy.ntheory.factor_ import totient
from sympy import primefactors
import sys
from types import ModuleType

# https://link.springer.com/referenceworkentry/10.1007/0-387-23483-7_367
def safe_prime(size):
    temp_size = size - 1
    while True:
        p = getPrime(size)
        check = (p * 2) + 1
        if isPrime(check):
            return check
    
def get_primitive_root(prime):
    p = prime - 1
    t = totient(p)
    factors = primefactors(p)
    tests = [p // factor for factor in factors]
    gen = 2
    found = True
    while True:
        for test in tests:
            ans = pow(gen, test, prime)
            if ans == 1:
                gen += 1
                found = False
                break 
        if found:
            return gen
        found = True

def string_hash_int(string: str, hash: ModuleType) -> int:
    return int.from_bytes(hash.new(data=string.encode()).digest(), sys.byteorder)

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, sys.byteorder)