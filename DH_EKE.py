from utils import *
from key_confirmation import *
from PAKE import PAKE_Protocol
import uuid
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from types import ModuleType

class DH_EKE(PAKE_Protocol):

    def __init__(self, id: uuid.UUID = None,
                hash: ModuleType = SHA256,
                secret: str = "WeakSecret",
                key_confirmation: Key_Confirmation = Key_Confirmation.CHALLENGES,
                symmetric_cipher: ModuleType = AES):

            self.symmetric_cipher = symmetric_cipher
            self.initiate_pass = [self.EKE_initiate_pass1, self.EKE_initiate_pass2, self.EKE_initiate_pass3]
            self.response_pass = [self.EKE_response_pass1, self.EKE_response_pass2]
            super().__init__(id, hash, secret, key_confirmation)

    def generate_parameters(self, size=1024, quick=False):
        if not quick:
            self.beta = safe_prime(size)
        else:
            self.beta = 349697669431510802115788926342782957761630007069497671657690678603704102113991242037175518265864638009405743676900428489019943598991220177983640838308917415760382668510838546409022312389060675536507946229098963356130387735339315375920925105125483435654418613427351689709209906655888565686621105810525235344503
        
        self.alpha = get_primitive_root(self.beta)
        print(f"Public Parameters:\n\tp: {self.beta}\n\tg: {self.alpha}\n\n")
        return (self.beta, self.alpha)

    def set_parameters(self, beta, alpha):
        self.beta = beta
        self.alpha = alpha

    def get_parameters(self):
        return (self.beta, self.alpha)

    def EKE_initiate_pass1(self):
        if not self.beta or not self.alpha:
            raise Exception('Finite Group not chosen')

        cipher = self.symmetric_cipher.new(key = self._secret, mode = self.symmetric_cipher.MODE_EAX)

        #randomly pick a and calculate g^a mod p
        self.private_key = randint(1, self.beta - 1)
        self.public_key_a = pow(self.alpha, self.private_key, self.beta)

        #encrypt g^A mod p with the secret key
        self.encrypted_public_key_a = cipher.encrypt(int_to_bytes(self.public_key_a))

        #send Alices id and the P(g^a)
        return self.id, (cipher.nonce, self.encrypted_public_key_a)

    def EKE_response_pass1(self, id_other, ciphertext):
        if not self.beta or not self.alpha:
            raise Exception('Finite Group not chosen')

        #log Alices id
        self.id_other = id_other

        cipher = self.symmetric_cipher.new(key = self._secret, mode = self.symmetric_cipher.MODE_EAX, nonce=ciphertext[0])

        #Decrypt Alices g^a
        self.public_key_a = int.from_bytes(cipher.decrypt(ciphertext[1]), sys.byteorder)

        #randomly pick a and calculate g^A mod p
        self.private_key = randint(1, self.beta - 1)
        self.public_key_b = pow(self.alpha, self.private_key, self.beta)

        #calculate session key
        self._sessionkey = pow(self.public_key_a, self.private_key, self.beta)
        self._sessionkey = self.hash.new(data=self._sessionkey.to_bytes(256, sys.byteorder)).hexdigest()

        cipher = self.symmetric_cipher.new(key = self._secret, mode = self.symmetric_cipher.MODE_EAX)
        ciphertext = (cipher.nonce, cipher.encrypt(int_to_bytes(self.public_key_b)))

        if self.key_confirmation == Key_Confirmation.CHALLENGES:
            self.challenge, key_confirmation_response = challenges_initiate_first_pass(self.beta, self.symmetric_cipher, self._secret)
            return self.id, ciphertext, key_confirmation_response

        return self.id, (cipher.nonce, cipher.encrypt(int_to_bytes(self.public_key_b)))

    def EKE_initiate_pass2(self, id_other, ciphertext, key_confirmation_response = None):
        self.id_other = id_other
        cipher1 = self.symmetric_cipher.new(key = self._secret, mode = self.symmetric_cipher.MODE_EAX, nonce=ciphertext[0])

        self.public_key_b = int.from_bytes(cipher1.decrypt(ciphertext[1]), sys.byteorder)

        self._sessionkey = pow(self.public_key_b, self.private_key, self.beta)
        self._sessionkey = self.hash.new(data=self._sessionkey.to_bytes(256, sys.byteorder)).hexdigest()

        if self.key_confirmation == Key_Confirmation.CHALLENGES:
            self.challenge, key_confirmation_response2 = challenges_response_first_pass(self.beta, self.symmetric_cipher, self._secret, key_confirmation_response)
            return key_confirmation_response2,
        return ()

    def EKE_response_pass2(self, key_confirmation_response=None):
        if self.key_confirmation == Key_Confirmation.CHALLENGES:
            key_confirmation_response2 = challenges_initiate_second_pass(self.symmetric_cipher, self._secret, key_confirmation_response[0], key_confirmation_response[1], self.challenge)
            return key_confirmation_response2,
        return ()

    def EKE_initiate_pass3(self, key_confirmation_response=None):
        if self.key_confirmation == Key_Confirmation.CHALLENGES:
            challenges_response_second_pass(self.symmetric_cipher, self._secret, key_confirmation_response, self.challenge)
            return ()
        return ()