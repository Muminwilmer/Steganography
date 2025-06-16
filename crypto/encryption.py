


class Encryption:
    @staticmethod
    def derive_bit_seed(source: bytes) -> bytes:
        import hashlib
        return hashlib.sha256(source).digest()

    @staticmethod
    def get_checksum(source: bytes) -> int:
        import hashlib
        return hashlib.sha256(source).digest()
    
    @staticmethod
    def get_bit_seed(password: bytes, paranoia_mode: bool = False, location_pin: str = None) -> int:
        if paranoia_mode:
            if not location_pin:
                raise ValueError("Location PIN required in paranoia mode")
            return Encryption.derive_bit_seed(location_pin)
        else:
            return Encryption.derive_bit_seed(password)
    
    @staticmethod
    def get_kdf_key(password: bytes, salt: bytes) -> bytes:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.hazmat.backends import default_backend

        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        return kdf.derive(password)

    @staticmethod
    def encrypt_bytes(password: bytes, data: bytes) -> bytes:
        import os
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        salt = os.urandom(16)
        key = Encryption.get_kdf_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return salt + nonce + ciphertext # returns in binary

    @staticmethod
    def decrypt_bytes(password: bytes, encrypted_data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        key = Encryption.get_kdf_key(password, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)