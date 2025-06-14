class PayloadBuilder:
    def __init__(self):
        self.files: list[tuple[bytes, str]] = []

    def add_file(self, data: bytes, ext: str) -> None:
        if not ext.startswith('.'):
            ext = '.' + ext
        self.files.append((data, ext))

    def build(self) -> bytes:
        out = bytearray()
        count = len(self.files)
        if count > 255:
            raise ValueError("Too many files (max 255)")

        out.append(count)  # 1 byte: number of files
        print(out)
        for data, ext in self.files:
            ext_bytes = ext.encode('utf-8')
            if len(ext_bytes) > 255:
                raise ValueError("Extension too long (max 255 bytes)")
            print(ext)
            out += len(data).to_bytes(4, "big")      # 4 bytes: data length
            out += data                              # variable: file data
            out.append(len(ext_bytes))               # 1 byte: ext length
            out += ext_bytes                         # variable: ext string

        return bytes(out)


class PayloadParser:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.index = 0

    def _read_bytes(self, length: int) -> bytes:
            if self.index + length > len(self.payload):
                raise ValueError("Malformed payload (unexpected end)")
            data = self.payload[self.index:self.index + length]
            self.index += length
            return data
    
    def parse(self) -> list[tuple[bytes, str]]:
        if len(self.payload) < 1:
            raise ValueError("Payload too short")

        count = self._read_bytes(1)[0]  # Number of files
        results = []

        for _ in range(count):
            # Read 4 bytes for data length
            data_len_bytes = self._read_bytes(4)
            data_len = int.from_bytes(data_len_bytes, 'big')

            # Read the file data
            data = self._read_bytes(data_len)

            # Read 1 byte for extension length
            ext_len = self._read_bytes(1)[0]

            # Read the extension string
            ext_bytes = self._read_bytes(ext_len)
            ext = ext_bytes.decode('utf-8')

            results.append((data, ext))

        return results