class lsbtools:
    def __init__(self, image_size, lsb_per_byte, bit_array):
        self.image_size = image_size
        self.lsb_per_byte = lsb_per_byte
        self.bit_array = bit_array
        self.lsb_lists = []
        # if args.force:
        #     print(f"⚠️ Increasing LSB from {args.lsb} to {min_lsb} to fit payload.")
        #     steg = StegFactory.load_stego_handler(args.input, min_lsb, forced_type=args.type)
        # else:
        #     raise ValueError(f"❌ Payload too large for LSB={args.lsb}. Required: {min_lsb}. Use --force to auto-increase.")

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
        # 💡 Handle auto-increase LSB if needed


    # @property
    # def lsb_per_byte(self):
    #     return self._lsb_per_byte

    # @lsb_per_byte.setter
    # def lsb_per_byte(self, value):
    #     self._lsb_per_byte = value
    #     self.lsb_lists = self._get_all_lsb()
        

    def _get_all_lsb(self) -> list[int]:
        import numpy as np
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
        import random
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