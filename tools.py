import os

class Tools:
    @staticmethod
    def extract_extension(file_path):
        file_name = os.path.basename(file_path)
        if '.' not in file_name:
            return ""  # no extension

        extensions = file_name.split('.', 1)[1]

        return extensions
    
    @staticmethod
    def read_file(file_path):
        if not os.path.exists(file_path):
            return None
        with open(file_path, "rb") as f:    
            binary = f.read()
        return binary