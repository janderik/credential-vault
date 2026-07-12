import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS = 600_000
KEY_LENGTH = 32

class VaultCrypto:
    def __init__(self, master_password=None, master_key=None):
        if master_key:
            self._key = master_key
        elif master_password:
            self._key = self._derive_key(master_password)
        else:
            self._key = os.urandom(KEY_LENGTH)
    def _derive_key(self, password):
        salt = self._load_or_create_salt()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LENGTH, salt=salt, iterations=KDF_ITERATIONS)
        return kdf.derive(password.encode())
    def _load_or_create_salt(self):
        sf = "vault.salt"
        if os.path.exists(sf):
            with open(sf, "rb") as f:
                return f.read()
        salt = os.urandom(SALT_SIZE)
        with open(sf, "wb") as f:
            f.write(salt)
        return salt
    def encrypt(self, plaintext):
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(self._key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return ciphertext, nonce, os.urandom(SALT_SIZE)
    def decrypt(self, ciphertext, nonce):
        aesgcm = AESGCM(self._key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    @staticmethod
    def generate_master_key():
        return base64.b64encode(os.urandom(KEY_LENGTH)).decode()
