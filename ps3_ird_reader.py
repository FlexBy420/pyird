import struct
import tkinter as tk
from tkinter import filedialog
#import gzip
import zlib

class IrdParser:
    def __init__(self, root):
        self.root = root
        self.root.title("PYIRD")

        self.label = tk.Label(root, text="Select PS3 IRD file:")
        self.label.pack(pady=10)

        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.pack(pady=10)

        self.text_output = tk.Text(root, height=20, width=80)
        self.text_output.pack(pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PS3 IRD Files", "*.ird")])
        if file_path:
            try:
                ird_info = self.parse_ird_file(file_path)
                if ird_info:
                    self.display_ird_info(ird_info)
            except Exception as e:
                self.display_error(str(e))

    def parse_ird_file(self, file_path):
        try:
            if is_gzipped(file_path):
                with open(file_path, 'rb') as gz_file:
                    content = zlib.decompress(gz_file.read(), zlib.MAX_WBITS | 16)
            else:
                with open(file_path, 'rb') as file:
                    content = file.read()

            # Read the magic string and check if it's a valid IRD file
            magic_string = content[:4]
            if magic_string != b'3IRD':
                raise ValueError("Not a valid IRD file")

            # Use struct module to unpack the binary data
            version, product_code, title_length = struct.unpack('<B9sB', content[4:15])
            title = content[15:15+title_length].decode('utf-8', errors='replace').rstrip('\0')
            ps3_system_version, version_str, app_version = struct.unpack('<5s5s5s', content[15+title_length:30+title_length])

            return {
                'IRDVersion': format_version(version),
                'ProductCode': product_code.decode('ascii', errors='replace').rstrip('\0'),
                'Title': title,
                'PS3SystemVersion': format_system_version(ps3_system_version.decode('ascii', errors='replace').strip('\0')),
                'GameVersion': format_version_string(version_str.decode('ascii', errors='replace').strip('\0')),
                'AppVersion': format_version_string(app_version.decode('ascii', errors='replace').strip('\0')),
            }

        except PermissionError:
            print(f"Skipped: {file_path} (File in use)")
        except Exception as e:
            print(f"Error parsing IRD file {file_path}: {e}")
            return None

    def display_ird_info(self, ird_info):
        self.text_output.delete(1.0, tk.END)  # Clear previous content
        formatted_info = self.format_ird_info(ird_info)
        self.text_output.insert(tk.END, formatted_info)

    def format_ird_info(self, ird_info):
        #formatted_info = f"IRD Version: {ird_info.get('IRDVersion', 'N/A')}\n"
        formatted_info = f"Title: {ird_info.get('Title', 'N/A')}\n"
        formatted_info += f"Game ID: {ird_info.get('ProductCode', 'N/A')}\n"
        formatted_info += f"Game Version: {ird_info.get('GameVersion', 'N/A')}\n"
        formatted_info += f"App Version: {ird_info.get('AppVersion', 'N/A')}\n"
        formatted_info += f"System Version: {ird_info.get('PS3SystemVersion', 'N/A')}\n"

        return formatted_info

    def display_error(self, error_message):
        self.text_output.delete(1.0, tk.END)
        self.text_output.insert(tk.END, f"Error: {error_message}")

def is_gzipped(file_path):
    with open(file_path, 'rb') as file:
        signature = file.read(2)
        return signature == b'\x1f\x8b'

def format_system_version(system_version):
    # Remove trailing zeros
    return system_version.rstrip('0')

def format_version_string(version_str):
    # Split version string into segments
    segments = version_str.split('.')

    # Ensure there are two segments and each segment has two digits
    if len(segments) == 2:
        formatted_version = f'{segments[0].zfill(2)}.{segments[1][:2]}'
    else:
        formatted_version = '00.00'
    return formatted_version

def format_version(version):
    # Ensure version has one or two digits, remove leading zero
    return str(int(version))

if __name__ == "__main__":
    root = tk.Tk()
    app = IrdParser(root)
    root.mainloop()