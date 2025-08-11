import sys
import struct
import gzip
from binascii import crc32
from io import BytesIO
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget,
    QLabel, QLineEdit, QPushButton, QFileDialog, QTreeWidget,
    QTreeWidgetItem, QTabWidget, QTextEdit, QMessageBox
)

def uncompress_gzip(data: bytes) -> bytes:
    return gzip.decompress(data)

class ISOHeader:
    def __init__(self, data: bytes):
        self.data = data
        self.block_size = 2048
        self.volume_space_size = 0
        self.files = []  # list of dicts
        self._parse()

    def _read_sector(self, sector_index):
        off = sector_index * self.block_size
        return self.data[off: off + self.block_size]

    def _scan_volume_descriptors(self):
        start = 16
        picked = None
        picked_enc = 'ascii'  # default
        i = start
        while True:
            if i * self.block_size >= len(self.data):
                break
            sec = self._read_sector(i)
            if len(sec) < 7:
                break
            vtype = sec[0]
            ident = sec[1:6]
            if ident != b'CD001':
                break
            if vtype == 2:
                # SVD (Joliet) - check escape sequences (0x25 0x2F 0x45) etc.
                # Joliet uses UCS-2 BE filenames in the SVD
                picked = sec
                picked_enc = 'utf-16-be'
                break
            if vtype == 1 and picked is None:
                picked = sec
                picked_enc = 'ascii'
            if vtype == 255:
                break
            i += 1
        return picked, picked_enc

    def _extract_root_record(self, desc):
        root_record = desc[156:156 + 34] 
        length = root_record[0]
        if length == 0:
            root_record = desc[156:156 + 2048]
        return root_record

    def _parse(self):
        desc, encoding = self._scan_volume_descriptors()
        if not desc:
            return
        self.volume_space_size = struct.unpack('<I', desc[80:84])[0]
        root_record = self._extract_root_record(desc)
        if len(root_record) < 14:
            return
        extent_loc = struct.unpack('<I', root_record[2:6])[0]
        data_len = struct.unpack('<I', root_record[10:14])[0]
        merged = {}
        order = []

        def read_dir(extent_loc_local, data_len_local, path):
            # Prevent infinite recursion by remembering visited extents
            visited_key = extent_loc_local
            if visited_key in read_dir.__dict__.setdefault('visited', set()):
                return
            read_dir.__dict__['visited'].add(visited_key)

            dir_offset = extent_loc_local * self.block_size
            dir_data = self.data[dir_offset: dir_offset + data_len_local]
            pos = 0
            last_name = None
            while pos < len(dir_data):
                length = dir_data[pos]
                if length == 0:
                    # advance to next sector boundary
                    pos = ((pos // self.block_size) + 1) * self.block_size
                    continue
                record = dir_data[pos: pos + length]
                if len(record) < 34:
                    break
                file_id_len = record[32]
                file_id_raw = record[33:33 + file_id_len]
                # Joliet uses UCS-2 BE (utf-16-be), PVD uses ASCII with ;1 suffix
                try:
                    if encoding == 'utf-16-be':
                        # file_id_raw length is in bytes and may be odd; decode as utf-16-be
                        fname = file_id_raw.decode('utf-16-be', errors='ignore')
                    else:
                        fname = file_id_raw.decode('ascii', errors='ignore')
                except Exception:
                    fname = file_id_raw.decode('latin-1', errors='ignore')

                # Remove version number suffixes like ;1 ;2 and trailing nulls
                fname = fname.split(';')[0].rstrip('\x00')

                extent = struct.unpack('<I', record[2:6])[0]
                size = struct.unpack('<I', record[10:14])[0]
                flags = record[25]

                # skip '.' and '..' which sometimes are represented as 0-length or special names
                if fname in ('.', '..', '') and (flags & 0x02):
                    pos += length
                    continue

                full_path = f"{path}/{fname}" if path else fname

                if flags & 0x02:
                    # directory: recurse
                    read_dir(extent, size, full_path)
                else:
                    # file: merge if already present (multi-extent). We'll key by full_path case-sensitively.
                    if full_path in merged:
                        # append extent piece and add size
                        merged[full_path]['extents'].append((extent, size))
                        merged[full_path]['size'] += size
                    else:
                        merged[full_path] = {
                            'name': full_path,
                            'first_extent': extent,
                            'extents': [(extent, size)],
                            'size': size
                        }
                        order.append(full_path)

                pos += length

        read_dir(extent_loc, data_len, path="")
        # Build files list preserving order
        self.files = [merged[name] for name in order]

    @property
    def disc_size_bytes(self):
        return self.volume_space_size * self.block_size

class IrdFile:
    def __init__(self, offset, md5_checksum):
        self.offset = offset
        self.md5_checksum = md5_checksum

class Ird:
    MAGIC = 0x44524933  # "3IRD" in little-endian

    def __init__(self):
        self.version = 0
        self.product_code = ""
        self.title = ""
        self.title_length = 0
        self.update_version = ""
        self.game_version = ""
        self.app_version = ""
        self.id = 0
        self.header_length = 0
        self.header = None
        self.footer_length = 0
        self.footer = None
        self.region_count = 0
        self.region_md5_checksums = []
        self.file_count = 0
        self.files = []
        self.file_hashes = {}
        self.unknown = 0
        self.pic = None
        self.data1 = None
        self.data2 = None
        self.uid = 0
        self.crc32 = 0
        self.disc_size = 0
        self.iso_files = []

class IrdParserGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PYIRDv2")
        self.setGeometry(100, 100, 900, 650)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        # File selection
        self.file_layout = QHBoxLayout()
        self.file_label = QLabel("IRD File:")
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_file)
        self.file_layout.addWidget(self.file_label)
        self.file_layout.addWidget(self.file_path)
        self.file_layout.addWidget(self.browse_button)
        self.layout.addLayout(self.file_layout)

        # Tabs
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        # Info tab
        self.info_tab = QWidget()
        self.info_layout = QVBoxLayout()
        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        self.info_layout.addWidget(self.info_text)
        self.info_tab.setLayout(self.info_layout)
        self.tabs.addTab(self.info_tab, "Info")

        # Files tab
        self.files_tab = QWidget()
        self.files_layout = QVBoxLayout()
        self.files_tree = QTreeWidget()
        self.files_tree.setHeaderLabels(["Filename", "Start Sector", "Size (bytes)", "MD5 Hash"])
        self.files_layout.addWidget(self.files_tree)
        self.files_tab.setLayout(self.files_layout)
        self.tabs.addTab(self.files_tab, "Files")

        # Hex view tab
        self.hex_tab = QWidget()
        self.hex_layout = QVBoxLayout()
        self.hex_text = QTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_layout.addWidget(self.hex_text)
        self.hex_tab.setLayout(self.hex_layout)
        self.tabs.addTab(self.hex_tab, "Hex View")

        self.current_ird = None

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select IRD File", "", "IRD Files (*.ird)")
        if file_path:
            self.file_path.setText(file_path)
            self.parse_file()

    def parse_file(self):
        file_path = self.file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Error", "Please select an IRD file first.")
            return
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            if content[:2] == b'\x1f\x8b':
                content = gzip.decompress(content)
            magic = struct.unpack('<I', content[:4])[0]
            if magic != Ird.MAGIC:
                raise ValueError("Not a valid IRD file")
            self.current_ird = self.parse_ird_content(content)
            self.display_ird_info()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to parse IRD file:\n{str(e)}")
            import traceback
            traceback.print_exc()

    def parse_ird_content(self, content):
        stream = BytesIO(content)
        result = Ird()

        # Magic
        stream.read(4)  # skip magic
        result.version = stream.read(1)[0]
        result.product_code = stream.read(9).decode('ascii')

        # Title
        title_length = stream.read(1)[0]
        result.title = stream.read(title_length).decode('utf-8')

        # Versions
        result.update_version = stream.read(4).decode('ascii')
        result.game_version = stream.read(5).decode('ascii')
        result.app_version = stream.read(5).decode('ascii')

        if result.version == 7:
            result.id = struct.unpack('<I', stream.read(4))[0]

        # Header/Footer
        result.header_length = struct.unpack('<I', stream.read(4))[0]
        result.header = stream.read(result.header_length)

        result.footer_length = struct.unpack('<I', stream.read(4))[0]
        result.footer = stream.read(result.footer_length)

        # Regions
        result.region_count = stream.read(1)[0]
        for _ in range(result.region_count):
            result.region_md5_checksums.append(stream.read(16))

        # Files
        result.file_count = struct.unpack('<I', stream.read(4))[0]
        for _ in range(result.file_count):
            offset = struct.unpack('<Q', stream.read(8))[0]
            md5_checksum = stream.read(16)
            result.files.append(IrdFile(offset, md5_checksum))

        result.unknown = struct.unpack('<I', stream.read(4))[0]

        # Version-specific fields
        if result.version == 9:
            result.pic = stream.read(115)
        result.data1 = stream.read(16)
        result.data2 = stream.read(16)
        if result.version < 9:
            result.pic = stream.read(115)

        # UID & CRC32
        result.uid = struct.unpack('<I', stream.read(4))[0]
        data_length = stream.tell()
        result.crc32 = struct.unpack('<I', stream.read(4))[0]

        calculated_crc = crc32(content[:data_length]) & 0xffffffff
        if result.crc32 != calculated_crc:
            print(f"Warning: CRC32 mismatch ({result.crc32:08x} != {calculated_crc:08x})")

        # Parse ISO
        try:
            header_data = uncompress_gzip(result.header)
            iso_header = ISOHeader(header_data)
            result.disc_size = iso_header.disc_size_bytes
            result.iso_files = iso_header.files
        except Exception as e:
            print("ISO parse failed:", e)

        return result

    def display_ird_info(self):
        if not self.current_ird:
            return

        self.info_text.clear()
        self.files_tree.clear()
        self.hex_text.clear()

        # Format PIC nicely (32 hex chars per line)
        pic_hex = self.current_ird.pic.hex() if self.current_ird.pic else ""
        formatted_pic = "\n".join(
            pic_hex[i:i+32] for i in range(0, len(pic_hex), 32)
        )

        # Build info string in consistent order
        info = (
            f"IRD File Information:\n\n"
            f"Version: {self.current_ird.version}\n"
            f"Product Code: {self.current_ird.product_code}\n"
            f"Title: {self.current_ird.title}\n"
            f"Update Version: {self.current_ird.update_version}\n"
            f"Game Version: {self.current_ird.game_version}\n"
            f"App Version: {self.current_ird.app_version}\n"
        )

        if self.current_ird.version == 7:
            info += f"ID: {self.current_ird.id}\n"

        info += (
            f"Header Length: {self.current_ird.header_length} bytes\n"
            f"Footer Length: {self.current_ird.footer_length} bytes\n"
            f"Region Count: {self.current_ird.region_count}\n"
            f"File Count: {self.current_ird.file_count}\n"
            f"UID: {self.current_ird.uid}\n"
            f"CRC32: {self.current_ird.crc32:08x}\n"
            f"Disc Size: {self.current_ird.disc_size:,} bytes\n\n"
            f"Data 1: {self.current_ird.data1.hex() if self.current_ird.data1 else ''}\n"
            f"Data 2: {self.current_ird.data2.hex() if self.current_ird.data2 else ''}\n\n"
            f"PIC:\n{formatted_pic}\n"
        )

        self.info_text.setPlainText(info)

        # File tree population
        for i, ird_file in enumerate(self.current_ird.files):
            if i < len(self.current_ird.iso_files):
                fdata = self.current_ird.iso_files[i]
                name = fdata['name']  # preserve case
                size = fdata['size']
            else:
                name = f"File {i}"
                size = ""
            item = QTreeWidgetItem(self.files_tree)
            item.setText(0, name)
            item.setText(1, f"{ird_file.offset}")
            item.setText(2, f"{size}")
            item.setText(3, ird_file.md5_checksum.hex())

        # Hex view (first 512 bytes of header)
        hex_data = bytes(self.current_ird.header[:512]) if self.current_ird.header else b''
        hex_text = '\n'.join(
            f"{i*16:08x}: {' '.join(f'{b:02x}' for b in hex_data[i*16:(i+1)*16])}"
            for i in range((len(hex_data) + 15) // 16)
        )
        self.hex_text.setPlainText(hex_text)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IrdParserGUI()
    window.show()
    sys.exit(app.exec())