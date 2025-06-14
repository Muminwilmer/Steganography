import os

class File:
    @staticmethod
    def extract_extension(file_path, last_only=False):
        file_name = os.path.basename(file_path)
        dot_pos = file_name.find('.')
        if dot_pos == -1:
            return ""

        if last_only:
            # Return extension after the last dot
            return file_name[file_name.rfind('.'):]
        else:
            # Return everything from the first dot to the end
            return file_name[dot_pos:]
    
    @staticmethod
    def read_file(file_path):
        if not os.path.exists(file_path):
            return None
        with open(file_path, "rb") as f:    
            binary = f.read()
        return binary