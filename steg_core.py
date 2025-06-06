from PIL import Image
import random
from tqdm import tqdm
from encryption import Encryption
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
    
    @staticmethod
    def build_payload(file_data: bytes, file_ext: str, password: bytes) -> bytes:
        ext_bytes = file_ext.encode("utf-8")
        
        if len(ext_bytes) > 255:
            raise ValueError("File extension too long")
        
        ext_len = len(ext_bytes).to_bytes(1, "big")
        data_len = len(file_data).to_bytes(4, "big")

        
        print("Encrypting payload")
        encrypted_payload = Encryption.encrypt_bytes(password, data_len + file_data + ext_len + ext_bytes)
        print("Encrypting payload length")
        payload_length = Encryption.encrypt_bytes(password, len(encrypted_payload).to_bytes(4, "big"))
        return payload_length + encrypted_payload # 0 checksum of payload add that to length too btw
        
    @staticmethod
    def parse_payload(payload: bytes) -> tuple[str, bytes]:
        #4B + 4B + file_data + 1B + ext_bytes
        i = 0
        data_len = int.from_bytes(payload[i:i+4])
        i += 4
        file_data = payload[i:i+data_len]
        i += data_len
        ext_len = int.from_bytes(payload[i:i+1])
        i += 1
        ext_bytes = payload[i:i+ext_len]
        
        ext_str = ext_bytes.decode('utf-8')

        return ext_str, file_data

    def __get_all_lsb(self, lsb_count: int = 1):
        total_lsb = len(self.bit_array) //8
        full_lsb_list = []


        for i in tqdm(range(total_lsb), unit="LSB", desc="Getting all possible LSBs"):  # Loop over each byte (pixel/channel)
            for j in range(lsb_count):  # Loop from LSB up to more significant bits
                bit_position = 7 - j  # 7 = LSB, 6 = 2nd LSB, etc.
                full_lsb_list.append((i * 8) + bit_position)
            
        return full_lsb_list
        
    # Returns "length" amount of random LSBs depending on the seed
    def list_random_lsb(self, needed_bits, seed, lsb_count):
        lsbList = self.__get_all_lsb(lsb_count)
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
            rng = random.Random(seed)
            bit_positions = rng.sample(lsbList, needed_bits)

        return bit_positions

    def fill_with_data(self, payload: bytes, seed: int, lsb_count: int = 1):
        data_bits = self.bytes_to_bits(payload)
        
        bit_positions = self.list_random_lsb(len(data_bits), seed, lsb_count)
        for i, bit in tqdm(enumerate(data_bits), unit="Bits", total=len(data_bits), desc="Filling LSBs with payload"):
            self.bit_array[bit_positions[i]] = bit

    def extract_data_from_image(self, seed: int, password: bytes, lsb_count: int = 1) -> bytes:
        payload_length_pos = self.list_random_lsb(48 * 8, seed, lsb_count)  # 32 bits = 4 bytes
        length_bits = [self.bit_array[i] for i in tqdm(payload_length_pos, unit="Bits", desc="Extracting payload length")]
        encrypted_length = bytes(self.bits_to_bytes(length_bits))
        print("Decrypting payload length")
        payload_length = int.from_bytes(Encryption.decrypt_bytes(password, encrypted_length), 'big') *8
        print(f"Payload is {payload_length} LSBs long")

        all_bit_positions = self.list_random_lsb(48 * 8 + payload_length, seed, lsb_count)
        payload_bits_pos = all_bit_positions[48 * 8:]

        payload_bits = [self.bit_array[i] for i in tqdm(payload_bits_pos, unit="Bits", desc="Extracting payload content")]
        return bytes(self.bits_to_bytes(payload_bits))


    def save_image(self, output_path):
        # Convert modified bit_array back to pixels and save the image
        byte_array = self.bits_to_bytes(self.bit_array)
        pixels = self.bytes_to_pixels(byte_array)
        
        new_image = Image.new(self.image.mode, self.image.size)
        new_image.putdata(pixels)
        new_image.save(output_path)