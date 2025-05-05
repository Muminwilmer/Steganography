from PIL import Image
from tqdm import tqdm
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import base64
import random
import string

def encrypt_text(password: str, plaintext: str) -> str:
    """
    Encrypts a given plaintext using AES-GCM with a derived key from the password.
    A salt and nonce are generated randomly for each encryption.

    Parameters:
    password (str): The password used to derive the encryption key.
    plaintext (str): The plain text to be encrypted.

    Returns:
    str: The encrypted text encoded in base64 for easy storage.
    """
    salt = os.urandom(16)  # Random salt for key derivation
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    key = kdf.derive(password.encode())  # Derive key from password and salt
    aesgcm = AESGCM(key)  # Initialize AES-GCM cipher
    nonce = os.urandom(12)  # Generate random nonce for encryption
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)  # Encrypt the text

    # Combine salt, nonce, and ciphertext, then encode as base64 for storage
    payload = base64.b64encode(salt + nonce + ciphertext).decode()
    return payload

def decrypt_text(password: str, encrypted_payload: str) -> str:
    """
    Decrypts an encrypted payload using AES-GCM with a derived key from the password.
    
    Parameters:
    password (str): The password used to derive the decryption key.
    encrypted_payload (str): The encrypted text in base64 format.

    Returns:
    str: The decrypted plaintext.
    """
    decoded = base64.b64decode(encrypted_payload)  # Decode the base64 encoded payload
    salt = decoded[:16]  # Extract salt from the payload
    nonce = decoded[16:28]  # Extract nonce
    ciphertext = decoded[28:]  # Extract ciphertext

    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    key = kdf.derive(password.encode())  # Derive the decryption key
    aesgcm = AESGCM(key)  # Initialize AES-GCM cipher for decryption
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)  # Decrypt the ciphertext
    return plaintext.decode()

def generate_random_garbage(length):
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation + " \n\t", k=length))


def open_image(image_path):
    img = Image.open(image_path).convert('RGB')
    return img

def extract_image_bytes(img):
    pixels = list(img.getdata())  # Extract pixel data
    flat_bytes = pixels_to_bytes(pixels)  # Convert pixels to bytes
    return flat_bytes

def save_image(pixels, size, output_path):
    img = Image.new("RGB", size)
    img.putdata(pixels)
    img.save(output_path)
    print(f"Saved image to {output_path}")

def pixels_to_bytes(pixels):
    return [channel for pixel in pixels for channel in pixel]

def bytes_to_pixels(byte_list):
    return [tuple(byte_list[i:i+3]) for i in range(0, len(byte_list), 3)]

def bytes_to_bits(byte_list):
    return [int(bit) for byte in byte_list for bit in format(byte, '08b')]

def bits_to_bytes(bits):
    return [int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)]

def fill_with_text(img, text, offset=0, text_density=1):
    image_bytes = extract_image_bytes(img)
    image_bits = bytes_to_bits(image_bytes)  # Convert image bytes to bits

    text_bytes = text.encode('utf-8')
    text_bits = bytes_to_bits(text_bytes)  # Convert text to bits
    length_bits = bytes_to_bits(len(text_bytes).to_bytes(4, byteorder='big'))  # Convert text length to bits

    total_bits_needed = len(length_bits) + len(text_bits)
    start = int(offset)
    available_bits = (len(image_bits) // 8) * text_density
    
    print(f"Message size: {total_bits_needed}")
    print(f"Extra offset: {start}")
    print(f"Useable space: {available_bits}")
    
    # Ensure there is enough space in the image for the message
    if (start + total_bits_needed) > available_bits:
        raise ValueError("Message is too large to hide in the image!")

    # Embed message length
    for i in tqdm(range(0, 32, text_density), desc="📝 Embedding length", unit="bits"):
        byte_index = start + i // text_density
        for j in range(text_density):
            if i + j >= 32:
                break
            bit = length_bits[i + j]
            bit_pos = byte_index * 8 + (7 - j)
            image_bits[bit_pos] = bit

    # Embed message
    for i in tqdm(range(0, len(text_bits), text_density), desc="📝 Embedding text", unit="bits"):
        byte_index = start + 32 // text_density + i // text_density
        for j in range(text_density):
            if i + j >= len(text_bits):
                break
            bit = text_bits[i + j]
            bit_pos = byte_index * 8 + (7 - j)
            image_bits[bit_pos] = bit

    return image_bits

def extract_text_from_image(img, offset=0, text_density=1):
    flat_bytes = extract_image_bytes(img)
    image_bits = bytes_to_bits(flat_bytes)
    start = int(offset)

    length_bits = []
    
    for i in tqdm(range(0, 32, text_density), desc="📝 Extracting length", unit="bits"):
        byte_index = start + (i // text_density)

        for bit_offset in range(text_density):
            bit_index = i + bit_offset
            if bit_index >= 32:
                break

            bit_position = byte_index * 8 + (7 - bit_offset)
            length_bits.append(image_bits[bit_position])

    length_bytes = bits_to_bytes(length_bits)
    message_length = int.from_bytes(length_bytes, byteorder='big')
    total_text_bits = message_length * 8

    # Extract actual message bits
    text_bits = []

    for i in tqdm(range(0, total_text_bits, text_density), desc="📝 Extracting text", unit="bits"):
        byte_index = start + (32 // text_density) + (i // text_density)

        for bit_offset in range(text_density):
            bit_index = i + bit_offset
            if bit_index >= total_text_bits:
                break

            bit_position = byte_index * 8 + (7 - bit_offset)
            text_bits.append(image_bits[bit_position])

    return bytes(bits_to_bytes(text_bits)).decode('utf-8')


def main():
    print("Mumin's Steganography tool!\n")
    
    mode = int(input("Add Text / Extract Text (1 / 0): ").strip())

    file_name = input("🖼️  Enter the image name:")
    image = open_image(file_name)
    image_disk_size = os.path.getsize(file_name)

    password = input("🔐 Enter the password or leave blank: ")
    
    print("\nThe text will always begin in the corner of an image, add an offset if you don't want this")
    offset = input("🔀 Text Offset (default 0) (BYTES): ")
    offset = int(offset.strip() or 0) * 8

    text_density = input("📦 Amount of text bits per image byte (default: 1) (max: 8): ")
    text_density = int(text_density.strip() or 1)
    text_density = min(max(text_density, 1), 8)

    usable_bits = image.size[0] * image.size[1] * 3 * text_density
    usable_chars = usable_bits // 8  # Since each ASCII character takes 8 bits

    # Displaying the info with the text_density impact
    print(f"📐 Image Size  : {image.size}")
    print(f"💾 Image Disk  : {image_disk_size} bytes")
    print(f"💿 Raw Capacity: {usable_chars} bytes ({usable_bits} bits)")
    print(f"📝 You can hide: ~{usable_chars-32-offset} ASCII characters (unencrypted) at {text_density} bits per byte and offset of {offset}. \n")

    if mode == 1:
        random_fill = input("🗑️  Fill with random garbage? (y/n):").strip().lower() == 'y'
        if random_fill:
            hidden_text = generate_random_garbage(usable_chars-32-offset)
            print("🔃 Filling with random garbage...")
        else:
            hidden_text = input("Enter the Hidden text you want to embed: ")
            if hidden_text.endswith(".txt"):
                print("Reading text file...")
                with open(hidden_text, "r", encoding="utf-8") as file:
                    hidden_text = file.read()
                    print(len(hidden_text))
        output_path = input(f"Output location (./steg_{file_name}): ").strip() or f"./steg_{file_name}"

        if password:
            print("🔃 Encrypts text..")
            hidden_text = encrypt_text(password, hidden_text)
            print(f"✅ Text encrypted: {hidden_text}\n")

        print("🔃 Adding hidden text to image...")
        new_image_bits = fill_with_text(image, hidden_text, offset, text_density)
        print("✅ Text added!\n")

        print("🔃 Putting the image back together..")
        new_pixels = bytes_to_pixels(bits_to_bytes(new_image_bits))
        save_image(new_pixels, image.size, output_path)
        print("✅ Complete!\n")
    else:
        print("🔃 Extracting text from the image")
        extracted_text = extract_text_from_image(image, offset, text_density)
        print("✅ Text extracted!\n")

        if password:
            try:
                print("🔃 Decrypting Text")
                extracted_text = decrypt_text(password, extracted_text)
                print("✅ Decrypted!\n")
            except Exception as e:
                print("❌ Incorrect password or data is corrupt.")
                return
        else:
            print("⚠️ No password entered!\n")
        response = input("🔽 Do you want to save the output to a file? (y/n) [y]: ").strip().lower() or "y"
        if response == "y":
            with open(file_name+".txt", "w", encoding="utf-8") as file:
                file.write(extracted_text)
        else:
            print("✅ Extracted Text:", extracted_text)


if __name__=="__main__":
    main()
