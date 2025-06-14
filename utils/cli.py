import argparse
from pathlib import Path
from PIL import Image

from crypto import PayloadBuilder, PayloadParser
from crypto import PayloadCrypto

from core import StegFactory

class cli:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Steganography Tool CLI (or interactive if no args)")
        subparsers = parser.add_subparsers(dest="command")

        # Embed command
        embed = subparsers.add_parser("embed")
        embed.add_argument("-i", "--input", help="Cover image")
        embed.add_argument("-o", "--output", help="Output image")
        embed.add_argument("-f", "--files", nargs='+', help="Files to embed")
        embed.add_argument("-p", "--password", required=True, help="Password")
        embed.add_argument("--lsb", type=range(int, 1, 8), help="LSB per byte", default=1)
        embed.add_argument("-s", "--seed", help="Seed for RNG Uses password by default")
        embed.add_argument("--force", action="store_true", help="Suppress LSB warning, increases to fit")

        # Extract command
        extract = subparsers.add_parser("extract")
        extract.add_argument("-i", "--input", help="Image to extract from")
        extract.add_argument("-p", "--password", required=True, help="Password")
        extract.add_argument("-s", "--seed", help="Seed for RNG Uses password by default")
        embed.add_argument("--lsb", type=range(int, 1, 8), help="LSB per byte", default=1)
        extract.add_argument("-o", "--output", help="Output directory")

        self.args = parser.parse_args()
        self.cli_mode()

    def cli_mode(self):
        args = self.args
        if args.command == "embed":
            self.cli_encrypt(args)
        elif args.command == "extract":
            self.cli_decrypt(args)

    def cli_encrypt(self, args):
        seed = (args.seed or args.password).encode()
        image = Image.open(args.input)
        builder = PayloadBuilder()

        for f in args.files:
            builder.add_file(Path(f).read_bytes(), Path(f).suffix)

        payload = builder.build()
        encrypted_payload = PayloadCrypto.encrypt_payload(args.password.encode(), payload)

        steg = StegFactory(image)


        steg.embed_payload(encrypted_payload, seed)
        steg.save_image(args.output)
        print(f"✅ Embedded into {args.output}")


    def cli_decrypt(self, args):
        seed = (args.seed or args.password).encode()
        image = Image.open(args.input)
        steg = StegCore(image)
        steg.lsb_per_byte = args.lsb
        encrypted = steg.extract_payload(seed, args.password.encode())
        decrypted = PayloadCrypto.decrypt_payload(args.password.encode(), encrypted)

        parser = PayloadParser(decrypted)
        files = parser.parse()

        out_dir = Path(args.output or "extracted")
        out_dir.mkdir(exist_ok=True)

        for idx, (data, ext) in enumerate(files):
            out_file = out_dir / f"file_{idx}{ext}"
            out_file.write_bytes(data)
            print(f"📝 Extracted: {out_file}")

        print("✅ Extraction done.")

