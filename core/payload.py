from core.crypto import Encryption

class PayloadBuilder:
    def __init__(self):
        self.files: list[tuple[bytes, str]] = []

    def add_file(self, data: bytes, ext: str) -> None:
        if not ext.startswith('.'):
            ext = '.' + ext
        self.files.append((data, ext))

    def build(self) -> bytes:
        out = bytearray()
        count = len(self.files)
        if count > 255:
            raise ValueError("Too many files (max 255)")

        out.append(count)  # 1 byte: number of files
        print(out)
        for data, ext in self.files:
            ext_bytes = ext.encode('utf-8')
            if len(ext_bytes) > 255:
                raise ValueError("Extension too long (max 255 bytes)")
            print(ext)
            out += len(data).to_bytes(4, "big")      # 4 bytes: data length
            out += data                              # variable: file data
            out.append(len(ext_bytes))               # 1 byte: ext length
            out += ext_bytes                         # variable: ext string

        return bytes(out)


class PayloadParser:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.index = 0

    def _read_bytes(self, length: int) -> bytes:
            if self.index + length > len(self.payload):
                raise ValueError("Malformed payload (unexpected end)")
            data = self.payload[self.index:self.index + length]
            self.index += length
            return data
    
    def parse(self) -> list[tuple[bytes, str]]:
        if len(self.payload) < 1:
            raise ValueError("Payload too short")

        count = self._read_bytes(1)[0]  # Number of files
        results = []

        for _ in range(count):
            # Read 4 bytes for data length
            data_len_bytes = self._read_bytes(4)
            data_len = int.from_bytes(data_len_bytes, 'big')

            # Read the file data
            data = self._read_bytes(data_len)

            # Read 1 byte for extension length
            ext_len = self._read_bytes(1)[0]

            # Read the extension string
            ext_bytes = self._read_bytes(ext_len)
            ext = ext_bytes.decode('utf-8')

            results.append((data, ext))

        return results


class PayloadCrypto:

    @staticmethod
    def encrypt_payload(password: bytes, data: bytes) -> bytes:
        """
        Encrypts the payload in two steps:

        1. Encrypts payload data (salt + nonce).

        2. Encrypts the length of the encrypted payload (4-byte length + salt + nonce)
           Fixed 48-byte encrypted header.
        
        Returns:
            bytes: concat
                - encrypted_header (48 bytes): AES-GCM encrypted length (4 bytes)
                - encrypted_data (variable length): AES-GCM encrypted payload

        Notes:
            Encryption.encrypt_bytes() produces encrypted bytes including
            salt and nonce prepended, so for 4-byte input, output length = 48 bytes.
        """

        # Encrypt the entire payload first
        encrypted_data = Encryption.encrypt_bytes(password, data)

        # Length of encrypted payload (Fixed 4B)
        payload_len_bytes = len(encrypted_data).to_bytes(4, 'big')

        # Encrypt the length, 4B + salt+nonce = 48
        encrypted_header = Encryption.encrypt_bytes(password, payload_len_bytes)

        if len(encrypted_header) != 48:
            raise ValueError(f"Encrypted header length unexpected: {len(encrypted_header)} bytes")

        return encrypted_header + encrypted_data

    @staticmethod
    def decrypt_payload(password: bytes, encrypted_payload: bytes, partial: bool = False) -> bytes:
        """
        Decrypts the payload encrypted by encrypt_payload.

        Args:
            password (bytes): Password used for decryption.
            encrypted_payload (bytes): The full encrypted payload bytes.

        Returns:
            bytes: The decrypted original payload data.
        """
        
        encrypted_header = encrypted_payload[:48]
        encrypted_data = encrypted_payload[48:]

        # Partial is used when first getting the length
        if partial:
            # If this warning turns on with your password backups start crying
            if len(encrypted_payload) < 48:
                raise ValueError("Encrypted payload too short to contain header")

            encrypted_header = encrypted_payload[:48]
            payload_len = int.from_bytes(Encryption.decrypt_bytes(password, encrypted_header), 'big')
            return payload_len
        
        # Decrypts payload with length part already stripped out
        decrypted_data = Encryption.decrypt_bytes(password, encrypted_data)

        return decrypted_data