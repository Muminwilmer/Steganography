from PIL import Image
import numpy as np
from tqdm import tqdm
import random

from crypto import PayloadCrypto
from core import StegCore
from library import Conversion

class StegoPNG(StegCore):
    def __init__(self, image, lsb_per_byte: int = 1):
        self.image = image.convert("RGB")

        # Use numPy for speed or smth
        arr = np.array(self.image) # Saves image to arr (RGB)
        self.shape = arr.shape  # Save shape
        byte_array = arr.flatten() # Save bytes
        self.bit_array = np.unpackbits(byte_array) # Make bytes to bits
        
        # Get all lsb locations
        self.lsb_per_byte = lsb_per_byte
        self.lsb_lists: list[int] = self._get_all_lsb()
        
    

    def embed_payload(self, payload: bytes, seed: bytes):
        data_bits = Conversion.bytes_to_bits(payload)
        
        bit_positions = self.list_random_lsb(len(data_bits), seed)
        self.bit_array[bit_positions] = data_bits

        # for i, bit in tqdm(enumerate(data_bits), unit="Bits", total=len(data_bits), desc="Filling LSBs with payload"):
        #     self.bit_array[bit_positions[i]] = bit

    def extract_payload(self, seed: bytes, password: bytes) -> bytes:
        # Extract encrypted header bits (48 bytes * 8 bits)
        header_bit_count = 48 * 8
        payload_length_pos = self.list_random_lsb(header_bit_count, seed)
        length_bits = [self.bit_array[i] for i in tqdm(payload_length_pos, unit="Bits", desc="Extracting payload length")]
        encrypted_length_bytes = bytes(Conversion.bits_to_bytes(length_bits))
        
        # Decrypts length bits (Partial returns in bits!)
        payload_length = PayloadCrypto.decrypt_payload(password, encrypted_length_bytes, partial=True)
        total_bits = header_bit_count + (payload_length * 8)

        all_bit_positions = self.list_random_lsb(total_bits, seed)

        # Extract payload bits after the header bits
        payload_bits = [self.bit_array[i] for i in tqdm(all_bit_positions, unit="Bits", desc="Extracting full payload content")]

        # Convert payload bits to bytes for decryption
        encrypted_payload_bytes = bytes(Conversion.bits_to_bytes(payload_bits))

        return encrypted_payload_bytes


    def save_image(self, output_path):
        # Convert modified bit_array back to pixels and save the image
        byte_array = np.packbits(self.bit_array)
        arr = byte_array.reshape(self.shape)
        img = Image.fromarray(arr.astype(np.uint8), "RGB")
        img.save(output_path)

    def min_lsb_for_payload(self, payloadlen: int) -> int:
        needed_bits = (payloadlen + 48 + 44) * 8
        capacity = self.image.size[0] * self.image.size[1] * 3 
        n = (needed_bits // capacity) + (needed_bits % capacity > 0)
        if n > 8:
            raise ValueError("Payload too large even with 8 LSBs")
        return max(1, n)

    def max_payload_size(self):
        capacity = (self.image.size[0] * self.image.size[1] * 3 * self._lsb_per_byte) // 8
        return capacity - 48 - 44

    @property
    def lsb_per_byte(self):
        return self._lsb_per_byte

    @lsb_per_byte.setter
    def lsb_per_byte(self, value):
        self._lsb_per_byte = value
        self.lsb_lists = self._get_all_lsb()
        

    def _get_all_lsb(self) -> list[int]:
        """Returns cached full LSB positions for the given LSB count."""
        if self.lsb_lists:
            return self.lsb_lists
        
        bytes_len = len(self.bit_array) // 8
        i = np.arange(bytes_len).repeat(self.lsb_per_byte)
        j = np.tile(np.arange(self.lsb_per_byte), bytes_len)

        self.lsb_lists = ((i * 8) + (7 - j)).tolist()
        return self.lsb_lists

        
    # Returns "length" amount of random LSBs depending on the seed
    def list_random_lsb(self, needed_bits, seed):
        lsbList = self._get_all_lsb()
        total_lsb = len(lsbList)
        
        if needed_bits > total_lsb:
            raise ValueError(
                f"Not enough LSBs in the image for the text entered.\n"
                f"📝: {needed_bits}, 🖼️: {total_lsb}, ⚖️: {total_lsb - needed_bits}"
            )
        
        if seed == "":
            print("No seed is being used")
            return lsbList[:needed_bits]
        else:
            seed_int = int.from_bytes(seed, 'big')
            rng = random.Random(seed_int)
            bit_positions = rng.sample(lsbList, needed_bits)

        return bit_positions