from utils import *
from key_confirmation import *
from PAKE import PAKE_Protocol
import uuid
from Crypto.Hash import SHA256
from types import ModuleType
from Crypto.Cipher import AES


class SPEKE(PAKE_Protocol):

    def __init__(self, id=None,
                hash = SHA256,
                secret="WeakSecret",
                key_confirmation: Key_Confirmation = Key_Confirmation.HASHES,
                patched:bool = True,
                symmetric_cipher: ModuleType = AES):

        self.initiate_pass = [self.SPEKE_pass1, self.SPEKE_pass3, self.SPEKE_pass5]
        self.response_pass = [self.SPEKE_pass2, self.SPEKE_pass4]
        
        self.symmetric_cipher = symmetric_cipher
        self.patched = patched
        super().__init__(id, hash, secret, key_confirmation)

    def generate_parameters(self, size=1024, quick=False):
        if not quick:
            self.beta = safe_prime(size)
        else:
            self.beta = 349697669431510802115788926342782957761630007069497671657690678603704102113991242037175518265864638009405743676900428489019943598991220177983640838308917415760382668510838546409022312389060675536507946229098963356130387735339315375920925105125483435654418613427351689709209906655888565686621105810525235344503
        
        self.g = pow(self._secret_int, 2, self.beta)
        print(f"Public Parameters:\n\tp: {self.beta}\n\n")
        return (self.beta,)

    def set_parameters(self, beta):
        self.beta = beta
        self.g = pow(self._secret_int, 2, self.beta)

    def get_parameters(self):
        return self.beta

    def SPEKE_pass1(self):
        if not self.beta or not self.g:
            raise Exception('Finite Group not chosen')

        #randomly pick a and calculate g^a mod p
        self.private_key = randint(1, self.beta - 1)

        self.public_key_a = pow(self.g, self.private_key, self.beta)

        return self.id, self.public_key_a,

    def SPEKE_pass2(self, other_id, public_key_b):

        self.other_id = other_id

        if not self.beta or not self.g:
            raise Exception('Finite Group not chosen')

        #randomly pick a and calculate g^a mod p
        self.private_key = randint(1, self.beta - 1)

        self.public_key_a = pow(self.g, self.private_key, self.beta)

        #Ensure public_key_b is in a valid range
        if public_key_b <=2 or public_key_b >= self.beta + 2:
            raise Exception("Recieved Value out of range")

        self.public_key_b = public_key_b

        if self.patched:

            self.sa = int.from_bytes(self.hash.new(data=int_to_bytes(self.public_key_a)).digest(), sys.byteorder)
            self.sb = int.from_bytes(self.hash.new(data=int_to_bytes(self.public_key_b)).digest(), sys.byteorder)
            maxs = max(self.sa, self.sb)
            mins = min(self.sa, self.sb)
            self.sid = int(str(maxs) + str(mins))

            skbytes = pow(self.public_key_b, self.private_key, self.beta)

            hash_interior = int_to_bytes(int(str(self.sid) + str(skbytes)))

            self._sessionkey = self.hash.new(data=hash_interior).hexdigest()

        else: 

            key = pow(self.public_key_b, self.private_key, self.beta)
            self._sessionkey = self.hash.new(data=int_to_bytes(key)).hexdigest()

        if self.key_confirmation == Key_Confirmation.HASHES:
            hashed = hashes_first_pass(bytes.fromhex(self._sessionkey), self.hash)
            return self.id, self.public_key_a, hashed
        elif self.key_confirmation == Key_Confirmation.CHALLENGES:
            self.challenge, key_confirmation_response = challenges_initiate_first_pass(self.beta, self.symmetric_cipher, self._secret)
            return self.id, self.public_key_a, key_confirmation_response
        return self.id, self.public_key_a,

    def SPEKE_pass3(self, other_id, public_key_b, key_confirmation):

        self.other_id = other_id

        #Ensure public_key_b is in a valid range
        if public_key_b <=2 or public_key_b >= self.beta + 2:
            raise Exception("Recieved Value out of range")

        self.public_key_b = public_key_b

        if self.patched:

            self.sa = int.from_bytes(self.hash.new(data=int_to_bytes(self.public_key_a)).digest(), sys.byteorder)
            self.sb = int.from_bytes(self.hash.new(data=int_to_bytes(self.public_key_b)).digest(), sys.byteorder)
            maxs = max(self.sa, self.sb)
            mins = min(self.sa, self.sb)
            self.sid = int(str(maxs) + str(mins))

            skbytes = pow(self.public_key_b, self.private_key, self.beta)

            hash_interior = int_to_bytes(int(str(self.sid) + str(skbytes)))

            self._sessionkey = self.hash.new(data=hash_interior).hexdigest()

        else: 

            key = pow(self.public_key_b, self.private_key, self.beta)
            self._sessionkey = self.hash.new(data=int_to_bytes(key)).hexdigest()
            

        if self.key_confirmation == Key_Confirmation.HASHES:
            hashed = hashes_second_pass(bytes.fromhex(self._sessionkey), self.hash, key_confirmation)
            return hashed,
        if self.key_confirmation == Key_Confirmation.CHALLENGES:
            self.challenge, key_confirmation_response2 = challenges_response_first_pass(self.beta, self.symmetric_cipher, self._secret, key_confirmation)
            return key_confirmation_response2,
        return ()

    def SPEKE_pass4(self, key_confirmation):
        if self.key_confirmation == Key_Confirmation.HASHES:
            hashes_third_pass(bytes.fromhex(self._sessionkey), self.hash, key_confirmation)
            return ()
        if self.key_confirmation == Key_Confirmation.CHALLENGES:
            key_confirmation_response2 = challenges_initiate_second_pass(self.symmetric_cipher, self._secret, key_confirmation[0], key_confirmation[1], self.challenge)
            return key_confirmation_response2,
        return ()

    def SPEKE_pass5(self, key_confirmation):
        if self.key_confirmation == Key_Confirmation.HASHES:
            return ()
        if self.key_confirmation == Key_Confirmation.CHALLENGES:
            challenges_response_second_pass(self.symmetric_cipher, self._secret, key_confirmation, self.challenge)
            return ()
        return ()