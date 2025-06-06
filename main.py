from PIL import Image

from steg_core import StegCore
from encryption import Encryption
from tools import Tools
from user_input import Prompt
import os



def display_intro():
    print("\n[ Mumin's Steganography Tool ]")
    print("Paranoia Mode:")
    print("  - Text encryption")
    print("  - Second password used as bit location seed")
    print("Normal Mode:")
    print("  - Text encryption (bit seed uses main password)")
    print("-" * 50)

def get_image_info(core: StegCore):
    print("\n📊 Image Information")
    print(f"(📐) Size         : {core.image.size}")
    print(f"(💿) Raw Capacity : {core.image.size[0] * core.image.size[1] * 3} bits")
    print(f"(📝) Text Capacity: ~{core.image.size[0] * core.image.size[1] * 3 // 8 - 4} characters\n")

def encrypt_flow(core: StegCore, password: str, bit_seed: int):
    print("\n[ Encrypt Mode ]")
    print("\nWriting more text using multiple passwords may corrupt hidden secrets!\n")
    while True:
        use_file = Prompt.bool("Embed a file instead of plain text?", default=True)

        if use_file:
            file_path = input("Enter path to the file to embed: ").strip()
            raw_data = Tools.read_file(file_path)
            if not raw_data:
                print("File doesn't exist or path is wrong. Remember to add filetype")
                continue

            file_ext = Tools.extract_extension(file_path)

            if file_ext.count(".") > 0:
                print("Multiple Extensions found! This is correct in some cases")
                print(f"Found: {file_ext[0]}")
                print("✅: [tar.gz]")
                print("❌: pdf.[png]")
                print("Make sure the extension is correct.")
                Prompt.string("Please re-type the extension name if wrong.", file_ext)
                if file_ext.startswith("."):
                    file_ext = file_ext[1:]

            if file_ext == "": 
                print("File extension is empty.")
                file_ext = "None"

            break
        else:
            raw_data = input("Enter your secret message: ").encode()
            file_ext = "txt"
            break

    

    payload = StegCore.build_payload(raw_data, file_ext, password)
    print(f"🔐 Payload encrypted. Preview: {payload[:30]}...")

    core.fill_with_data(payload, bit_seed)
    output_path = Prompt.string("Enter output image path", "out.png")
    core.save_image(output_path)

def decrypt_flow(core: StegCore, password: str, bit_seed: int):
    print("\n[ Decrypt Mode ]")
    extracted_payload = core.extract_data_from_image(bit_seed, password)
    print("Decrypting payload")
    decrypted_payload = Encryption.decrypt_bytes(password, extracted_payload)

    print("Parsing payload")
    file_ext, file_data = StegCore.parse_payload(decrypted_payload)


    save_file = True
    show_output = False

    if file_ext == "txt" or file_ext == "None":
        save_file = Prompt.bool("Save the output to a file?", default=True)
        if not save_file:
            show_output = True

    if save_file:
        file_ext = file_ext if not file_ext == "None" else ""
        output_path = Prompt.string("Where should the file be saved?", f"output.{file_ext}")
        with open(output_path, "wb") as f:
            f.write(file_data)
        print(f"(✅) Saved extracted output to {output_path}")

    if show_output:
        print("(✅) Extracted Text:\n", file_data)


def obfuscate_flow(core: StegCore, password: str, bit_seed: int):
    print("\n[ Obfuscate Mode ]")
    encrypted_len = len(core.extract_text_from_image(bit_seed))

    # use obfuscator.py to generate random letters and numbers
    # encrypt them to make it look real
    # add them using real seed and adding everywhere there's not stuff already


    

def main():
    display_intro()
    paranoia_mode = Prompt.bool("Enable Paranoia mode (separate passwords)?", default=False)

    image_path = input("Enter image filename (with extension): ").strip()
    if not os.path.exists(image_path):
        print("❌ File not found.")
        return

    image = Image.open(image_path)
    core = StegCore(image)
    get_image_info(core)
    print("\n")

    password = Prompt.password("Enter your encryption password: ")
    if paranoia_mode:
        location_pin = Prompt.password("Enter a separate password for bit locations: ")
    else:
        location_pin = password

    bit_seed = Encryption.derive_bit_seed(location_pin)
    if bit_seed == "":
        print('Bit seed is empty, Secrets will be "hidden" left-to-right along the image.')


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
