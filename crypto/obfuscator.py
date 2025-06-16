class Obfuscator:
    @staticmethod
    def generate_random_text(length: int) -> str:
        import random
        import string
        chars = string.ascii_letters + string.digits  # A-Z, a-z, 0-9
        return ''.join(random.choice(chars) for _ in range(length))