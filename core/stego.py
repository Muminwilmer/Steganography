from PIL import Image
import random
import math
from tqdm import tqdm
from core.crypto import Encryption
from core.payload import PayloadCrypto

class StegCore:
    def __init__(self, image, lsb_per_byte: int = 1):
        self.image = image.convert("RGB")
        # Gets the image bits from the pixels
        pixels = list(self.image.getdata())
        # Converts pixels to bytes then bytes to bits.
        self.bit_array = self.bytes_to_bits(self.pixels_to_bytes(pixels))
        self.lsb_lists = []
        self.lsb_per_byte = lsb_per_byte


    @staticmethod
    def pixels_to_bytes(pixels):
        return [channel for pixel in pixels for channel in pixel]

    @staticmethod
    def bytes_to_bits(byte_list):
        return [int(bit) for byte in byte_list for bit in format(byte, '08b')]

    @staticmethod
    def bits_to_bytes(bits):
        return [int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)]

    @staticmethod
    def bytes_to_pixels(byte_list):
        return [tuple(byte_list[i:i+3]) for i in range(0, len(byte_list), 3)]
    
    def min_lsb_for_payload(self, payloadlen: int) -> int:
        needed_bits = (payloadlen + 48 + 44) * 8

        capacity = self.image.size[0] * self.image.size[1] * 3 

        n = (needed_bits // capacity) + (needed_bits % capacity > 0)

        if n > 8:
            raise ValueError("Payload too large even with 8 LSBs")
        return max(1, n)

    
    def max_payload_size(self):
        # Encryption overhead:
        # Header encryption: 4 bytes (payload length) + 16 (salt) + 12 (nonce) + 16 (tag) = 48 bytes total
        # Payload encryption overhead: 16 (salt) + 12 (nonce) + 16 (tag) = 44 bytes total
        # Max payload data size is capacity - overhead 
        # Width * Height * 3 (RGB) * 1 (LSB per byte default: 1) // 8 (Makes bits) 
        capacity = (self.image.size[0] * self.image.size[1] * 3 * self._lsb_per_byte) // 8
        return capacity - 48 - 44

    @property
    def lsb_per_byte(self):
        return self._lsb_per_byte

    @lsb_per_byte.setter
    def lsb_per_byte(self, value):
        self._lsb_per_byte = value
        self.lsb_lists = []  # Reset cache
        self._get_all_lsb()

    def _get_all_lsb(self) -> list[int]:
        """Returns cached full LSB positions for the given LSB count."""
        if self.lsb_lists:
            return self.lsb_lists

        full_lsb_list = [
            (i * 8) + (7 - j)
            for i in range(len(self.bit_array) // 8)
            for j in range(self.lsb_per_byte)
        ]

        self.lsb_lists = full_lsb_list
        return full_lsb_list

        
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

    def embed_payload(self, payload: bytes, seed: bytes):
        data_bits = self.bytes_to_bits(payload)
        
        bit_positions = self.list_random_lsb(len(data_bits), seed)
        for i, bit in tqdm(enumerate(data_bits), unit="Bits", total=len(data_bits), desc="Filling LSBs with payload"):
            self.bit_array[bit_positions[i]] = bit

    def extract_payload(self, seed: bytes, password: bytes) -> bytes:
        # Extract encrypted header bits (48 bytes * 8 bits)
        header_bit_count = 48 * 8
        payload_length_pos = self.list_random_lsb(header_bit_count, seed)
        length_bits = [self.bit_array[i] for i in tqdm(payload_length_pos, unit="Bits", desc="Extracting payload length")]
        encrypted_length_bytes = bytes(self.bits_to_bytes(length_bits))
        
        # Decrypts length bits (Partial returns in bits!)
        payload_length = PayloadCrypto.decrypt_payload(password, encrypted_length_bytes, partial=True)
        total_bits = header_bit_count + (payload_length * 8)

        all_bit_positions = self.list_random_lsb(total_bits, seed)

        # Extract payload bits after the header bits
        payload_bits = [self.bit_array[i] for i in tqdm(all_bit_positions, unit="Bits", desc="Extracting full payload content")]

        # Convert payload bits to bytes for decryption
        encrypted_payload_bytes = bytes(self.bits_to_bytes(payload_bits))

        return encrypted_payload_bytes


    def save_image(self, output_path):
        # Convert modified bit_array back to pixels and save the image
        byte_array = self.bits_to_bytes(self.bit_array)
        pixels = self.bytes_to_pixels(byte_array)
        
        new_image = Image.new(self.image.mode, self.image.size)
        new_image.putdata(pixels)
        new_image.save(output_path)