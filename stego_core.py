from PIL import Image
import random
from tqdm import tqdm

class StegoCore:
    def __init__(self, image):
        self.image = image.convert("RGB")
        self.pixels = list(self.image.getdata())

        # Gets the image bytes from the pixels
        self.byte_array = self.pixels_to_bytes(self.pixels)
        self.bit_array = self.bytes_to_bits(self.byte_array)

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
    
    # Returns "length" amount of random LSBs depending on the seed
    def list_random_lsb(self, length, seed):
        total_bytes = len(self.byte_array)

        if length > total_bytes:
            raise ValueError("Not enough bits in the image to hide the data.")

        rng = random.Random(seed)
        positions = rng.sample(range(total_bytes), length)

        bit_positions = [(byte_index * 8) + 7 for byte_index in positions]
        return bit_positions

    def fill_with_text(self, text, seed):
        text_bytes = text.encode('utf-8')
        text_bits = self.bytes_to_bits(len(text_bytes).to_bytes(4, 'big') + text_bytes) # length of text + text content, then converts to bits

        bit_positions = self._get_bit_positions(len(text_bits), seed) # Gets a random list of LSBs from the seed

        for i, bit in enumerate(text_bits):
            self.bit_array[bit_positions[i]] = bit

    def extract_text_from_image(self, seed: int):
        length_bits_pos = self._get_bit_positions(32, seed) # Gets 32 LSBs depending on the seed
        length_bits = [self.bit_array[i] for i in length_bits_pos]
        message_length = int.from_bytes(self.bits_to_bytes(length_bits), 'big')

        total_bits = message_length * 8
        all_bit_positions = self._get_bit_positions(32 + total_bits, seed) # Gets list of LSBs from seed
        text_bits_pos = all_bit_positions[32:]  # Skip first 32 (length)

        text_bits = [self.bit_array[i] for i in text_bits_pos]
        return bytes(self.bits_to_bytes(text_bits)).decode('utf-8')

    def save_image(self, output_path):
        new_bytes = self.bits_to_bytes(self.bit_array)
        new_pixels = self.bytes_to_pixels(new_bytes)
        img = Image.new("RGB", self.image.size)
        img.putdata(new_pixels)
        img.save(output_path)
        print(f"Saved image to {output_path}")