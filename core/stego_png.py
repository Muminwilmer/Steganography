from core import StegCore


class StegoPNG(StegCore):
    def __init__(self, image, lsb_per_byte: int = 1):
        import numpy as np
        from .stegotools import lsbtools

        self.image = image.convert("RGB")

        # Use numPy for speed or smth
        arr = np.array(self.image) # Saves image to arr (RGB)
        self.shape = arr.shape  # Save shape
        byte_array = arr.flatten() # Save bytes
        self.bit_array = np.unpackbits(byte_array) # Make bytes to bits

        self.tools = lsbtools(self.image.size, lsb_per_byte, self.bit_array)

        # Get all lsb locations
        self.lsb_per_byte = lsb_per_byte
        self.lsb_lists: list[int] = self.tools._get_all_lsb()

        
        
    

    def embed_payload(self, payload: bytes, seed: bytes):
        from utils import Conversion
        data_bits = Conversion.bytes_to_bits(payload)
        
        bit_positions = self.tools.list_random_lsb(len(data_bits), seed)
        self.bit_array[bit_positions] = data_bits

        # for i, bit in tqdm(enumerate(data_bits), unit="Bits", total=len(data_bits), desc="Filling LSBs with payload"):
        #     self.bit_array[bit_positions[i]] = bit

    def extract_payload(self, seed: bytes, password: bytes) -> bytes:
        from utils import Conversion
        from crypto import PayloadCrypto
        from tqdm import tqdm
        # Extract encrypted header bits (48 bytes * 8 bits)
        header_bit_count = 48 * 8
        payload_length_pos = self.tools.list_random_lsb(header_bit_count, seed)
        length_bits = [self.bit_array[i] for i in tqdm(payload_length_pos, unit="Bits", desc="Extracting payload length")]
        encrypted_length_bytes = bytes(Conversion.bits_to_bytes(length_bits))
        
        # Decrypts length bits (Partial returns in bits!)
        payload_length = PayloadCrypto.decrypt_payload(password, encrypted_length_bytes, partial=True)
        total_bits = header_bit_count + (payload_length * 8)

        all_bit_positions = self.tools.list_random_lsb(total_bits, seed)

        # Extract payload bits after the header bits
        payload_bits = [self.bit_array[i] for i in tqdm(all_bit_positions, unit="Bits", desc="Extracting full payload content")]

        # Convert payload bits to bytes for decryption
        encrypted_payload_bytes = bytes(Conversion.bits_to_bytes(payload_bits))

        return encrypted_payload_bytes


    def save_file(self, output_path):
        import numpy as np
        from PIL import Image
        # Convert modified bit_array back to pixels and save the image
        byte_array = np.packbits(self.bit_array)
        arr = byte_array.reshape(self.shape)
        img = Image.fromarray(arr.astype(np.uint8), "RGB")
        img.save(output_path)

