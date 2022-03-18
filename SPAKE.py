from utils import *
from key_confirmation import *
from PAKE import PAKE_Protocol
import uuid
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from types import ModuleType


class SPAKE(PAKE_Protocol):

    def __init__(self, id=None,
                hash = SHA256,
                secret="WeakSecret",
                key_confirmation: Key_Confirmation = Key_Confirmation.HASHES,
                version:int = 2,
                symmetric_cipher: ModuleType = AES):

        self.initiate_pass = [self.SPAKE_pass1, self.SPAKE_pass3, self.SPAKE_pass5]
        self.response_pass = [self.SPAKE_pass2, self.SPAKE_pass4]
        
        self.symmetric_cipher = symmetric_cipher
        self.version = version
        super().__init__(id, hash, secret, key_confirmation)

    def generate_parameters(self, size=1024, quick=False):
        if not quick:
            self.beta = safe_prime(size)
        else:
            self.beta = 349697669431510802115788926342782957761630007069497671657690678603704102113991242037175518265864638009405743676900428489019943598991220177983640838308917415760382668510838546409022312389060675536507946229098963356130387735339315375920925105125483435654418613427351689709209906655888565686621105810525235344503
        self.g = get_primitive_root(self.beta)
        self.m = randint(1, self.beta - 1)
        self.n = randint(1, self.beta - 1)
        print(f"Public Parameters:\n\tp: {self.beta}\n\tg: {self.g}\n\tm: {self.m}\n\tn: {self.n}\n\n")
        return (self.beta, self.g, self.m, self.n)

    def set_parameters(self, beta, g, m, n):
        self.beta = beta
        self.g = g
        self.m = m
        self.n = n

    def get_parameters(self):
        return self.beta, self.g, self.m, self.n

    def SPAKE_pass1(self):
        if not self.beta or not self.g:
            raise Exception('Finite Group not chosen')

        #randomly pick a and calculate g^a mod p
        self.private_key = randint(1, self.beta - 1)

        self.public_key_a = pow(self.g, self.private_key, self.beta)

        self.m_exponent = pow(self.m, self._secret_int, self.beta)
        self.n_exponent = pow(self.n, self._secret_int, self.beta)

        self.public_key_a_prime = (self.public_key_a * self.m_exponent) % self.beta

        return self.id, self.public_key_a_prime

    def SPAKE_pass2(self, other_id, public_key_b):

        self.other_id = other_id
        
        if not self.beta or not self.g:
            raise Exception('Finite Group not chosen')
        
        self.public_key_b_prime = public_key_b

        #randomly pick a and calculate g^a mod p
        self.private_key = randint(1, self.beta - 1)

        self.public_key_a = pow(self.g, self.private_key, self.beta)

        self.m_exponent = pow(self.m, self._secret_int, self.beta)
        self.n_exponent = pow(self.n, self._secret_int, self.beta)

        self.public_key_a_prime = (self.public_key_a * self.n_exponent) % self.beta

        self.key = (self.public_key_b_prime * pow(self.m_exponent, -1, self.beta)) % self.beta
        self.key = pow(self.key, self.private_key, self.beta)

        if self.version == 1:
            self._sessionkey = str(self.other_id) +("\n")\
                + str(self.id) +("\n")\
                + str(self.public_key_b_prime)+("\n") \
                + str(self.public_key_a_prime)+("\n") \
                + str(self.key)
        else:
            self._sessionkey = str(self.other_id)+("\n") \
                + str(self.id) +("\n")\
                + str(self.public_key_b_prime) +("\n")\
                + str(self.public_key_a_prime) +("\n")\
                + str(self._secret) +("\n")\
                + str(self.key)

        self._sessionkey = self.hash.new(data = self._sessionkey.encode()).hexdigest()

        if self.key_confirmation == Key_Confirmation.HASHES:
            hashed = hashes_first_pass(bytes.fromhex(self._sessionkey), self.hash)
            return self.id, self.public_key_a_prime, hashed
        elif self.key_confirmation == Key_Confirmation.CHALLENGES:
            self.challenge, key_confirmation_response = challenges_initiate_first_pass(self.beta, self.symmetric_cipher, self._secret)
            return self.id, self.public_key_a_prime, key_confirmation_response
        return self.id, self.public_key_a_prime,

    def SPAKE_pass3(self, other_id, public_key_b, key_confirmation):

        self.other_id = other_id
        
        self.public_key_b_prime = public_key_b

        self.key = (self.public_key_b_prime * pow(self.n_exponent, -1, self.beta)) % self.beta
        self.key = pow(self.key, self.private_key, self.beta)

        if self.version == 1:
            self._sessionkey = str(self.id) +("\n")\
                + str(self.other_id) +("\n")\
                + str(self.public_key_a_prime) +("\n")\
                + str(self.public_key_b_prime) +("\n")\
                + str(self.key)
        else:
            self._sessionkey = str(self.id) +("\n")\
                + str(self.other_id) +("\n")\
                + str(self.public_key_a_prime) +("\n")\
                + str(self.public_key_b_prime) +("\n")\
                + str(self._secret) +("\n")\
                + str(self.key)

        self._sessionkey = self.hash.new(data = self._sessionkey.encode()).hexdigest()

        
            

        if self.key_confirmation == Key_Confirmation.HASHES:
            hashed = hashes_second_pass(bytes.fromhex(self._sessionkey), self.hash, key_confirmation)
            return hashed,
        if self.key_confirmation == Key_Confirmation.CHALLENGES:
            self.challenge, key_confirmation_response2 = challenges_response_first_pass(self.beta, self.symmetric_cipher, self._secret, key_confirmation)
            return key_confirmation_response2,
        return ()

    def SPAKE_pass4(self, key_confirmation):
        if self.key_confirmation == Key_Confirmation.HASHES:
            hashes_third_pass(bytes.fromhex(self._sessionkey), self.hash, key_confirmation)
            return ()
        if self.key_confirmation == Key_Confirmation.CHALLENGES:
            key_confirmation_response2 = challenges_initiate_second_pass(self.symmetric_cipher, self._secret, key_confirmation[0], key_confirmation[1], self.challenge)
            return key_confirmation_response2,
        return ()

    def SPAKE_pass5(self, key_confirmation):
        if self.key_confirmation == Key_Confirmation.HASHES:
            return ()
        if self.key_confirmation == Key_Confirmation.CHALLENGES:
            challenges_response_second_pass(self.symmetric_cipher, self._secret, key_confirmation, self.challenge)
            return ()
        return ()