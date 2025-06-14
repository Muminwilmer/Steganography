from abc import ABC, abstractmethod

class StegCore(ABC):
    def __init__(self, image, lsb_per_byte: int = 1):
        self.image = image
        self.lsb_per_byte = lsb_per_byte

    @abstractmethod
    def embed_payload(self, payload: bytes, seed: bytes):
        pass

    @abstractmethod
    def extract_payload(self, seed: bytes, password: bytes) -> bytes:
        pass

    @abstractmethod
    def save_image(self, output_path: str):
        pass