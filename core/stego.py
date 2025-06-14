from PIL import Image

from library import File

from core import StegCore
from core import StegoPNG
# from core.types.stego_jpg import StegoJPEG

class StegFactory:
    def load_stego_handler(filepath: str, lsb_per_byte: int = 1) -> StegCore:
        ext = File.extract_extension(filepath).lower()
        if ext in ['']:
            return None
        
        if ext in ['.png']:
            image = Image.open(filepath)
            return StegoPNG(image, lsb_per_byte)
        
        # elif ext in ['.jpg', '.jpeg']:
        #     image = Image.open(filepath)
        #     return StegoJPEG(image, lsb_per_byte)
        
        # elif ext in ['.wav']: return StegoAudio(...)
        
        else:
            raise ValueError(f"Unsupported file format: {ext}")
