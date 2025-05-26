from PIL import Image
from stego_core import StegoCore
from encryption import Encryption
import os

def prompt_bool(prompt: str, default=True) -> bool:
    choice = input(f"{prompt} ({'Y/n' if default else 'y/N'}): ").strip().lower()
    return choice == "" and default or choice == "y"

def display_intro():
    print("\n[ Mumin's Steganography Tool ]")
    print("Paranoia Mode:")
    print("  - Text encryption")
    print("  - Second password used as bit location seed")
    print("Normal Mode:")
    print("  - Text encryption (bit seed uses main password)")
    print("-" * 50)

def get_image_info(core: StegoCore):
    print("\n📊 Image Information")
    print(f"(📐) Size         : {core.image.size}")
    print(f"(💿) Raw Capacity : {core.image.size[0] * core.image.size[1] * 3} bits")
    print(f"(📝) Text Capacity: ~{core.image.size[0] * core.image.size[1] * 3 // 8 - 4} characters\n")

def get_passwords(paranoia: bool) -> tuple[str, str]:
    password = input("Enter your encryption password: ")
    if paranoia:
        pin = input("Enter a separate password for bit locations (long + strong): ")
    else:
        pin = password
    return password, pin

def encrypt_flow(core: StegoCore, password: str, bit_seed: int):
    print("\n[ Encrypt Mode ]")
    print("\nWriting more text using multiple passwords may corrupt hidden secrets!\n")
    use_file = prompt_bool("Embed a file instead of plain text?", default=False)

    if use_file:
        file_path = input("Enter path to the file to embed: ").strip()
        with open(file_path, "r", encoding="utf-8") as f:
            plaintext = f.read()
    else:
        plaintext = input("Enter your secret message: ")

    encrypted_text = Encryption.encrypt_text(password, plaintext)
    print(f"🔐 Text encrypted. Preview: {encrypted_text[:30]}...")

    core.fill_with_text(encrypted_text, bit_seed)
    output_path = input("Enter output image path (e.g., out.png): ") or "out.png"
    core.save_image(output_path)

def decrypt_flow(core: StegoCore, password: str, bit_seed: int):
    print("\n[ Decrypt Mode ]")
    decrypted_text = Encryption.decrypt_text(password, core.extract_text_from_image(bit_seed))

    if prompt_bool("Save the output to a file?", default=True):
        output_path = input("Where should the file be saved (e.g., ./output.txt): ") or "output.txt"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(decrypted_text)
        print(f"(✅) Saved extracted text to {output_path}")
    else:
        print("(✅) Extracted Text:\n", decrypted_text)

def obfuscate_flow(core: StegoCore, password: str, bit_seed: int):
    print("\n[ Obfuscate Mode ]")

    # use obfuscator.py to generate random letters and numbers
    # encrypt them to make it look real
    # add them using real seed and adding everywhere there's not stuff already
    

def main():
    display_intro()
    paranoia_mode = prompt_bool("Enable Paranoia mode (separate passwords)?", default=False)

    image_path = input("Enter image filename (with extension): ").strip()
    if not os.path.exists(image_path):
        print("❌ File not found.")
        return

    image = Image.open(image_path)
    core = StegoCore(image)
    get_image_info(core)

    password, location_pin = get_passwords(paranoia_mode)
    bit_seed = Encryption.derive_bit_seed(location_pin)

    mode = input("Choose mode - Encrypt (E) / Decrypt (D) / Obfuscate (O): ").strip().lower()
    if mode.startswith("e"):
        encrypt_flow(core, password, bit_seed)
    elif mode.startswith("d"):
        decrypt_flow(core, password, bit_seed)
    elif mode.startswith("o"):
        obfuscate_flow(core, password, bit_seed)
    else:
        print("❌ Invalid option selected.")

if __name__ == "__main__":
    main()
