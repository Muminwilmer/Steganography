import numpy as np

class Conversion:
    @staticmethod
    def pixels_to_bytes(pixels):
        return np.array(pixels, dtype=np.uint8).flatten()

    @staticmethod
    def bytes_to_bits(byte_array: bytes) -> np.ndarray:
        return np.unpackbits(np.frombuffer(byte_array, dtype=np.uint8))

    @staticmethod
    def bits_to_bytes(bit_array: bytearray) -> bytes:
        return np.packbits(bit_array).tobytes()

    @staticmethod
    def bytes_to_pixels(byte_array):
        if isinstance(byte_array, bytes):
            byte_array = np.frombuffer(byte_array, dtype=np.uint8)

        reshaped = byte_array.reshape((-1, 3))  # reshape to Nx3
        return [tuple(pixel) for pixel in reshaped]
    