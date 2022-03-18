from enum import Enum
from Crypto.Random.random import randint
from utils import *
import sys
from Crypto.Util.number import size
import uuid

class Key_Confirmation(Enum):
    NONE = 0
    CHALLENGES = 1
    HASHES = 2
    ZKP = 3

#bob generates a challenge
def challenges_initiate_first_pass(modulus, symmetric_cipher, key):
    #pick a random challenge from 1 to p-1
    challenge = randint(1, modulus - 1)

    #encrypt the challenge with the secret key
    cipher = symmetric_cipher.new(key = key, mode = symmetric_cipher.MODE_EAX)

    #return the encrypted challenge
    return challenge, (cipher.nonce, cipher.encrypt(int_to_bytes(challenge)))

#alice verifies she can read the challenge and makes one of her own
def challenges_response_first_pass(modulus, symmetric_cipher, key, challenge):
    #decrypt the challenge
    cipher = symmetric_cipher.new(key = key, mode = symmetric_cipher.MODE_EAX, nonce=challenge[0])
    challenge_calc = int.from_bytes(cipher.decrypt(challenge[1]), sys.byteorder)
    
    #pick a random challenge from 1 to p-1
    challenge_new = randint(1, modulus - 1)

    #encrypt the new challenge and the old challenge with the secret key
    cipher = symmetric_cipher.new(key = key, mode = symmetric_cipher.MODE_EAX)
    cipher2 = symmetric_cipher.new(key = key, mode = symmetric_cipher.MODE_EAX)

    #return the encrypted challenge
    return challenge_new, ((cipher.nonce, cipher.encrypt(int_to_bytes(challenge_new))), (cipher2.nonce, cipher2.encrypt(int_to_bytes(challenge_calc))))

#bob verifies alice was able to read his challenge and verifies he can read hers
def challenges_initiate_second_pass(symmetric_cipher, key, challengea, challengeb, challengeb_ans):
    #decrypt the challenge
    cipher = symmetric_cipher.new(key = key, mode = symmetric_cipher.MODE_EAX, nonce=challengea[0])
    challengea = int.from_bytes(cipher.decrypt(challengea[1]), sys.byteorder)

    #decrypt the challenge
    cipher = symmetric_cipher.new(key = key, mode = symmetric_cipher.MODE_EAX, nonce=challengeb[0])
    challengeb = int.from_bytes(cipher.decrypt(challengeb[1]), sys.byteorder)

    #verify that alice knows the secret key
    if challengeb_ans != challengeb:
        raise Exception("Key Confirmation Failure: Challenges do not match.")

    #encrypt the challenge with the secret key
    cipher = symmetric_cipher.new(key = key, mode = symmetric_cipher.MODE_EAX)

    #return the encrypted challenge
    return (cipher.nonce, cipher.encrypt(int_to_bytes(challengea)))

#alice verifies she can read bobs challenge
def challenges_response_second_pass(symmetric_cipher, key, challengea, challengea_ans):
    #decrypt the challenge
    cipher = symmetric_cipher.new(key = key, mode = symmetric_cipher.MODE_EAX, nonce=challengea[0])
    challengea = int.from_bytes(cipher.decrypt(challengea[1]), sys.byteorder)

    #verify that alice knows the secret key
    if challengea != challengea_ans:
        raise Exception("Key Confirmation Failure: Challenges do not match.")

def hashes_first_pass(session_key, hash):
    single_hash = hash.new(data=session_key).digest()
    double_hash = hash.new(data=single_hash).digest()
    return double_hash

def hashes_second_pass(session_key, hash, hashed):
    single_hash = hash.new(data=session_key).digest()
    double_hash = hash.new(data=single_hash).digest()

    if double_hash != hashed:
        raise Exception("Key Confirmation Failure: Hashes do not match.")

    return single_hash

def hashes_third_pass(session_key, hash, hashed):
    single_hash = hash.new(data=session_key).digest()

    if single_hash != hashed:
        raise Exception("Key Confirmation Failure: Hashes do not match.")

def schnorr_proof_prover(p, q, g, hash, a, user_ID: uuid.UUID, other_info = None):
    user_ID = user_ID.int

    v = randint(0, q-1)
    validator = pow(g, v, p)

    challenge_interior = size(g).to_bytes(4, sys.byteorder) + int_to_bytes(g) + \
                        size(validator).to_bytes(4, sys.byteorder) + int_to_bytes(validator) + \
                        size(a).to_bytes(4, sys.byteorder) + int_to_bytes(a) + \
                        size(user_ID).to_bytes(4, sys.byteorder) + int_to_bytes(user_ID)

    if other_info is not None:
        challenge_interior = challenge_interior + size(other_info).to_bytes(4, sys.byteorder) + other_info.to_bytes(math.ceil(size(other_info) / 8), sys.byteorder)

    challenge = hash.new(data=challenge_interior)

    challenge = int.from_bytes(challenge.digest(), sys.byteorder)

    result = (v - (a * challenge)) % q

    return validator, challenge, result

def schnorr_proof_validator(p, q, g, validator, challenge, result, a):
    #A is within [1, p-1]
    if a < 1 or a >= p:
        print("Public key is not in the correct range")
        return False
    #A^q = 1 mod p
    if pow(a, q, p) != 1:
        print("public key is not of the correct order")
        return False
    #V = g^r * A^c mod p
    if validator != ((pow(g, result, p) * pow(a, challenge, p)) % p):
        print("validation failed")
        return False
    return True