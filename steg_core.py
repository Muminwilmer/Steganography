from PIL import Image
import random
from tqdm import tqdm

class StegCore:
    def __init__(self, image):
        self.image = image.convert("RGB")
        # Gets the image bits from the pixels
        pixels = list(self.image.getdata())
        # Converts pixels to bytes then bytes to bits.
        self.bit_array = self.bytes_to_bits(self.pixels_to_bytes(pixels))

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
    def list_random_lsb(self, needed_bits, seed):
        total_lsb = len(self.bit_array) //8

        if needed_bits > total_lsb:
            raise ValueError(
                f"Not enough LSBs in the image for the text entered.\n"
                f"📝: {needed_bits}, 🖼️: {total_lsb}, ⚖️: {total_lsb - needed_bits}"
            )
        
        if seed == 0:
            print("No seed is being used")
            bit_positions = [(i * 8) + 7 for i in range(needed_bits)]
        else:
            rng = random.Random(seed)
            all_lsb_indices = [(i * 8) + 7 for i in range(total_lsb)]
            bit_positions = rng.sample(all_lsb_indices, needed_bits)

        return bit_positions

    def fill_with_text(self, text, seed):
        text_bytes = text.encode('utf-8')
        text_bits = self.bytes_to_bits(len(text_bytes).to_bytes(4, 'big') + text_bytes) # length of text + text content, then converts to bits

        bit_positions = self.list_random_lsb(len(text_bits), seed) # Gets a random list of LSBs from the seed
        for i, bit in enumerate(text_bits):
            self.bit_array[bit_positions[i]] = bit

    def extract_text_from_image(self, seed: int):
        length_bits_pos = self.list_random_lsb(32, seed) # Gets 32 LSBs depending on the seed
        length_bits = [self.bit_array[i] for i in length_bits_pos]
        message_length = int.from_bytes(self.bits_to_bytes(length_bits), 'big')

        total_bits = message_length * 8

        all_bit_positions = self.list_random_lsb(32 + total_bits, seed) # Gets list of LSBs from seed
        text_bits_pos = all_bit_positions[32:]  # Skip first 32 (length)

        text_bits = [self.bit_array[i] for i in text_bits_pos]
        return bytes(self.bits_to_bytes(text_bits)).decode('utf-8')

    def save_image(self, output_path):
        # Convert modified bit_array back to pixels and save the image
        byte_array = self.bits_to_bytes(self.bit_array)
        pixels = self.bytes_to_pixels(byte_array)
        
        new_image = Image.new(self.image.mode, self.image.size)
        new_image.putdata(pixels)
        new_image.save(output_path)