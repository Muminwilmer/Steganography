from abc import ABC, abstractmethod
class StegCore(ABC):
    def __init__(self, image):
        self.image = image



    @abstractmethod
    def embed_payload(self, payload: bytes, seed: bytes):
        pass

    @abstractmethod
    def extract_payload(self, seed: bytes, password: bytes) -> bytes:
        pass

    @abstractmethod
    def save_file(self, output_path: str):
        pass

class StegFactory:
    @staticmethod
    def load_stego_handler(filepath: str, forced_type: str = None) -> StegCore:
        from PIL import Image
        from utils import File

        ext = File.extract_extension(filepath).lower()

        if not ext and forced_type:
            ext = f".{forced_type.lower()}"
        elif not ext:
            raise ValueError("File has no extension and no forced type was provided. --type")

        
        if ext in ['.png']:
            from core import StegoPNG
            image = Image.open(filepath)
            return StegoPNG(image)
        
        # elif ext in ['.jpg', '.jpeg']:
        #     image = Image.open(filepath)
        #     return StegoJPEG(image, lsb_per_byte)
        
        # elif ext in ['.wav']: return StegoAudio(...)
        
        else:
            raise ValueError(f"Unsupported file format: {ext}")



"""
BMP	 Excellent	Simple, uncompressed
PNG	 ✅ Very good	Lossless 
WAV	 Very good	Audio LSB
TIFF Good	Large, lossless
FLAC Good	Audio, lossless
AVI	 Possible	Depending on compression
"""
