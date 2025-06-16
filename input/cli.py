import argparse
from pathlib import Path

from crypto import PayloadBuilder, PayloadParser, PayloadCrypto
from core import StegFactory


class cli:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Steganography Tool CLI")
        subparsers = parser.add_subparsers(dest="command")

        # Embed command
        embed = subparsers.add_parser("embed", help="Embed files into an image")
        embed.add_argument("-i", "--input", required=True, help="Cover image")
        embed.add_argument("-f", "--files", nargs='+', required=True, help="Files to embed")
        embed.add_argument("-o", "--output", required=True, help="Output image path")
        embed.add_argument("-p", "--password", required=True, help="Password")
        embed.add_argument("-s", "--seed", help="Seed for RNG (defaults to password)")


        embed.add_argument("-t", "--type", help="Force a stego type (e.g., png)")
        embed.add_argument("--lsb", type=int, default=1, choices=range(1, 9), help="LSB per byte (1-8)")

        embed.add_argument("--force", action="store_true", help="Suppress LSB warning, increase if needed")

        # Extract command
        extract = subparsers.add_parser("extract", help="Extract files from an image")
        extract.add_argument("-i", "--input", required=True, help="Image to extract from")
        extract.add_argument("-p", "--password", required=True, help="Password")

        extract.add_argument("-s", "--seed", help="Seed for RNG (defaults to password)")

        extract.add_argument("-o", "--output", help="Directory to extract files to")
        extract.add_argument("-t", "--type", help="Force a stego type (e.g., png)")
        extract.add_argument("--lsb", type=int, default=1, choices=range(1, 9), help="LSB per byte (1-8)")
        

        self.args = parser.parse_args()
        self.cli_mode()

    def cli_mode(self):
        if self.args.command == "embed":
            self.cli_encrypt()
        elif self.args.command == "extract":
            self.cli_decrypt()
        else:
            print("❌ No command provided. Use 'embed' or 'extract'.")
    
    def cli_encrypt(self):
        args = self.args
        seed = (args.seed or args.password).encode()

        builder = PayloadBuilder()
        for f in args.files:
            builder.add_file(Path(f).read_bytes(), Path(f).suffix)
        payload = builder.build()

        encrypted_payload = PayloadCrypto.encrypt_payload(args.password.encode(), payload)

        # 💡 Pass forced type to StegFactory
        steg = StegFactory.load_stego_handler(args.input, forced_type=args.type)

        steg.embed_payload(encrypted_payload, seed)
        steg.save_file(args.output)
        print(f"✅ Embedded into {args.output}")

    def cli_decrypt(self):
        args = self.args
        seed = (args.seed or args.password).encode()

        steg = StegFactory.load_stego_handler(args.input, forced_type=args.type)

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
