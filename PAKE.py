import abc
from types import ModuleType
import uuid
from Crypto.Hash import SHA256
from key_confirmation import *
from utils import *

class PAKE_Protocol:
    def __init__(self, id: uuid.UUID = None,
                hash: ModuleType = SHA256,
                secret: str = "WeakSecret",
                key_confirmation: Key_Confirmation = Key_Confirmation.HASHES):

        #id is a unique identifier
        if id is None:
            self.id = uuid.uuid4()
        else:
            self.id = id

        #hash function used in the protocol
        self.hash = hash

        #secret used in the protocol
        self._sec = secret
        self._secret = self.hash.new(data=self._sec.encode()).digest()
        self._secret_int = string_hash_int(self._sec, self.hash)

        #derived session key
        self._sessionkey = None

        self.symmetric = False

        #if key confirmation is used and which key
        self.key_confirmation = key_confirmation

        @property
        @abc.abstractmethod
        def intiate_pass(self):
            pass
        
        @property
        @abc.abstractmethod
        def response_pass(self):
            pass

    @abc.abstractmethod
    def generate_parameters():
        pass

    @abc.abstractmethod
    def set_parameters():
        pass

    @abc.abstractmethod
    def get_parameters():
        pass

    def get_session_key(self):
        return self._sessionkey

    def set_secret(self, secret):
        self._sec = secret
        self._secret = string_hash_int(self.sec, self.hash)