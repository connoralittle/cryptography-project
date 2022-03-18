from utils import *
from key_confirmation import *
from PAKE import PAKE_Protocol
import uuid
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from types import ModuleType
from Crypto.PublicKey import DSA
from Crypto.Random.random import randint
import uuid
from Crypto.Hash import SHA256
import sys
import math
from utils import *

class JPake(PAKE_Protocol):

    def __init__(self, id=None, 
                hash=SHA256, 
                secret="WeakSecret",
                key_confirmation: Key_Confirmation = Key_Confirmation.NONE):
        self.initiate_pass = [self.JPake_first_pass, self.JPake_second_pass, self.JPake_third_pass]
        self.response_pass = [self.JPake_first_pass, self.JPake_second_pass, self.JPake_third_pass]

        super().__init__(id, hash, secret, key_confirmation)

        self.symmetric = True

    # Groups are chosen with the same parameters as DSA as of https://datatracker.ietf.org/doc/html/rfc8236
    # DSA PARAMETERS:

    # This Standard specifies the following choices for the pair L and N (the bit lengths of p and q, respectively):
    
    #     L = 1024, N = 160
    #     L = 2048, N = 224
    #     L = 2048, N = 256
    #     L = 3072, N = 256
    def generate_parameters(self, size=2048):
        DSAkey=DSA.generate(size)
        self.p, self.q, self.g = DSAkey.p, DSAkey.q, DSAkey.g
        print(f"Public Parameters:\n\tp: {self.p}\n\tq: {self.q}\n\tg: {self.g}\n\n")
        return self.p, self.q, self.g

    def get_parameters(self):
        return self.p, self.q, self.g

    def set_parameters(self, p, q, g):
        self.p, self.q, self.g = p, q, g

    def JPake_first_pass(self):

        if not self.p or not self.q or not self.g:
            raise Exception('Finite Group not chosen')

        self.x1 = randint(0, self.q-1)
        self.x2 = randint(1, self.q-1)

        self.g1 = pow(self.g, self.x1, self.p)
        self.g2 = pow(self.g, self.x2, self.p)

        self.validator1, self.challenge1, self.result1 = schnorr_proof_prover(self.p, self.q, self.g, self.hash, self.x1, self.id)
        self.validator2, self.challenge2, self.result2 = schnorr_proof_prover(self.p, self.q, self.g, self.hash, self.x2, self.id)

        return self.id, self.g1, self.g2, (self.validator1, self.challenge1, self.result1, self.g1), (self.validator2, self.challenge2, self.result2, self.g2)

    def JPake_second_pass(self, user_ID, g1, g2, proof1, proof2):
        self.other_ID = user_ID

        if not schnorr_proof_validator(self.p, self.q, self.g, *proof1) or not schnorr_proof_validator(self.p, self.q, self.g, *proof2):
            raise Exception('Discrete Log ZKP Verification Failed')

        self.g3 = g1
        self.g4 = g2
        e = (self.x2 * self._secret_int)

        a = (self.g1 * self.g3 * self.g4) % self.p
        a = pow(a, e, self.p)

        pk = pow(self.g, e, self.p)

        self.validator3, self.challenge3, self.result3 = schnorr_proof_prover(self.p, self.q, self.g, self.hash, e, self.other_ID)

        return a, (self.validator3, self.challenge3, self.result3, pk)

    def JPake_third_pass(self, a, proof1):
        if not schnorr_proof_validator(self.p, self.q, self.g, *proof1):
            raise Exception('Discrete Log ZKP Verification Failed')

        temp = pow(self.g4, self.x2, self.p)
        temp = pow(temp, self._secret_int, self.p)

        temp = pow(temp, -1, self.p)
        key = (a * temp) % self.p
        key = pow(key, self.x2, self.p)

        self._sessionkey = self.hash.new(data=key.to_bytes(256, sys.byteorder)).hexdigest()
