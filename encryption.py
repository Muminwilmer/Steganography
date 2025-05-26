from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import hashlib
import base64

class Encryption:
    @staticmethod
    def derive_bit_seed(source: str) -> int:
        return int.from_bytes(hashlib.sha256(source.encode()).digest(), 'big')

    @staticmethod
    def get_bit_seed(password: str, paranoia_mode: bool = False, location_pin: str = None) -> int:
        if paranoia_mode:
            if not location_pin:
                raise ValueError("Location PIN required in paranoia mode")
            return Encryption.derive_bit_seed(location_pin)
        else:
            return Encryption.derive_bit_seed(password)
    
    @staticmethod
    def get_kdf_key(password: str, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        return kdf.derive(password.encode())


    @staticmethod
    def encrypt_text(password: str, plaintext: str) -> str:
        salt = os.urandom(16)
        key = Encryption.get_kdf_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        payload = base64.b64encode(salt + nonce + ciphertext).decode()
        return payload

    @staticmethod
    def decrypt_text(password: str, encrypted_payload: str) -> str:
        data = base64.b64decode(encrypted_payload)
        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]
        key = Encryption.get_kdf_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()