from PIL import Image

from core import StegFactory, StegCore
from crypto import Encryption, PayloadBuilder, PayloadCrypto, PayloadParser

from library import File, Prompt
from utils import cli
import 
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
    print(f"(📐) Size            : {core.image.size}")
    print(f"(📝) Payload Capacity: ~{core.max_payload_size()} bytes\n")
    print(f"(💡) This can be increased with lsb per byte at the cost of detectability")

def encrypt_flow(core: StegCore, password: bytes, bit_seed: bytes):
    print("\n[ Encrypt Mode ]")
    pb = PayloadBuilder()
    while True:
        use_file = Prompt.bool("Embed a file instead of plain text?", default=True)

        if use_file:
            file_path = input("Enter path to the file to embed: ").strip()
            raw_data = File.read_file(file_path)
            if not raw_data:
                print("File doesn't exist or path is wrong. Remember to add filetype")
                continue

            file_ext = File.extract_extension(file_path)
            if file_ext.count('.') > 1:
                print("Multiple Extensions found! This is correct in some cases")
                print(f"Found: {file_ext}")
                print("✅: file[.tar.gz]")
                print("❌: file[.homework.png]")
                file_ext = Prompt.string("Please re-type the extension name if wrong.", file_ext)

            if file_ext == "":
                print("File extension is empty.")
                file_ext = ".None"  # Lets hope no one uses the .none filetype

            pb.add_file(raw_data, file_ext)
        else:
            text_data = input("Enter your secret message: ").encode('utf-8')
            pb.add_file(text_data, '.txt')

        if Prompt.bool("Do you want to add more files", False):
            continue
        break

    payload = pb.build()
    payloadlen = len(payload)
    maxlen = core.max_payload_size()

    if payloadlen > maxlen:
        smallestLSB = core.min_lsb_for_payload(payloadlen)
        print(f"(⚠️) Your payload is too large for the current image!")
        print(f"(📦) {payloadlen} > (🖼️) {maxlen}")
        print(f"(💡) You can increase the LSB per Byte, currently set to {core.lsb_per_byte}")
        print(f"(⚠️) This will significantly increase detectability.")
        print(f"(⚠️) Anything above 2 is NOT recommended!")
        print(f"(⚠️) You'll need an LSB per byte of {smallestLSB}")

        if smallestLSB > 2:
            print(f"(⚠️❌) Increasing above 2 makes steganography much easier to detect with the naked eye!")
            if not Prompt.bool("(⚠️❌) Are you sure you want to do this? You could use a bigger or multiple images instead.", False):
                return
        core.lsb_per_byte = Prompt.num("Do you want to increase the LSB per byte?", smallestLSB, smallestLSB, 8)
        core._get_all_lsb()
        get_image_info(core)


    print("Payload built, encrypting...")
    encrypted_payload = PayloadCrypto.encrypt_payload(password, payload)
    print(f"Encrypted payload length: {len(encrypted_payload)} bytes")

    core.embed_payload(encrypted_payload, bit_seed)
    output_path = Prompt.string("Enter output image path", "out.png")
    core.save_image(output_path)

def decrypt_flow(core: StegCore, password: bytes, bit_seed: bytes):
    print("\n[ Decrypt Mode ]")
    encrypted_payload = core.extract_payload(bit_seed, password)
    
    print("Decrypting payload")
    decrypted_payload = PayloadCrypto.decrypt_payload(password, encrypted_payload)

    parser = PayloadParser(decrypted_payload)
    files = parser.parse()  

    for i, (data, ext) in enumerate(files):
        print("\n" + "-"*40)
        print(f"\nFile {i+1}: Extension: {ext}, Size: {len(data)} bytes")

        save_file = True
        show_output = False

        if ext == '.None':
            ext = ""

        if ext == '.txt':
            show_output = Prompt.bool("Show output in console?", default=True)
            save_file = Prompt.bool("Also save to file?", default=True)

        if save_file:
            out_name = Prompt.string("Where should the file be saved?", f"output_{i}{ext}")
            try:
                with open(out_name, "wb") as f:
                    f.write(data)
                print(f"(✅) Saved extracted output to {out_name}")
            except Exception as e:
                print(f"(❌) Failed to save file: {e}")


        if show_output:
            try:
                text = data.decode('utf-8')
                print("(✅) Extracted Text:\n", text)
            except Exception as e:
                print("Could not decode text:", e)


def obfuscate_flow(core: StegCore, password: bytes, bit_seed: bytes):
    print("\n[ Obfuscate Mode ]")
    encrypted_len = len(core.extract_text_from_image(bit_seed))

    # use obfuscator.py to generate random letters and numbers
    # encrypt them to make it look real
    # add them using real seed and adding everywhere there's not stuff already


    

def main():
    import sys
    if len(sys.argv) > 1:
        print(sys.argv)
        cli()
    else:
        display_intro()
        paranoia_mode = Prompt.bool("Enable Paranoia mode (separate passwords)?", default=False)

        image_path = input("Enter image filename (with extension): ").strip()
        if not os.path.exists(image_path):
            print("❌ File not found.")
            return

        core = StegFactory.load_stego_handler(image_path)

        get_image_info(core)
        print("\n")

        password = Prompt.password("Enter your encryption password: ")
        if paranoia_mode:
            location_pin = Prompt.password("Enter a separate password for bit locations: ")
        else:
            location_pin = password

        bit_seed = Encryption.derive_bit_seed(location_pin)
        if not bit_seed:
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
