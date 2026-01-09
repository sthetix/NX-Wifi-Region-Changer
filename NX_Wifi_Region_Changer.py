import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, PhotoImage, messagebox
import hashlib
import os
import shutil
import sys
import platform
import ctypes
import struct

# Set DPI awareness for Windows
if platform.system() == "Windows":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except AttributeError:
        pass

# Determine script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def resource_path(relative_path):
    """Get absolute path to resource, handling PyInstaller."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = SCRIPT_DIR
    return os.path.join(base_path, relative_path)

def check_icon_files():
    """Check if wifi.ico and wifi.png exist."""
    wifi_ico_path = resource_path("wifi.ico")
    wifi_png_path = resource_path("wifi.png")
    if not os.path.exists(wifi_ico_path):
        messagebox.showerror("Error", f"wifi.ico not found in {wifi_ico_path}.")
        sys.exit(1)
    if not os.path.exists(wifi_png_path):
        messagebox.showerror("Error", f"wifi.png not found in {wifi_png_path}.")
        sys.exit(1)

check_icon_files()

# Constants
VALID_FILENAMES = {"prodinfo.bin", "prodinfo", "PRODINFO", "PRODINFO.bin"}
CRC_16_TABLE = [
    0x0000, 0xCC01, 0xD801, 0x1400, 0xF001, 0x3C00, 0x2800, 0xE401,
    0xA001, 0x6C00, 0x7800, 0xB401, 0x5000, 0x9C01, 0x8801, 0x4400
]
REGION_CODE_MAP = {
    "America": b"\x52\x32\x00\x00",
    "Asia (Singapore)": b"\x55\x31\x00\x00",
    "Asia (Malaysia)": b"\x55\x34\x00\x00",
    "Australia": b"\x55\x32\x00\x00",
    "Europe": b"\x52\x31\x00\x00",
    "Japan": b"\x54\x31\x00\x00",
}
REGION_MAP = {v.hex().upper(): k for k, v in REGION_CODE_MAP.items()}
DEBUG_MODE = True

def get_crc_16(data):
    """Calculate CRC-16, matching Atmosphere's GetCrc16."""
    crc = 0x55AA
    for byte in data:
        r = CRC_16_TABLE[crc & 0x0F]
        crc = ((crc >> 4) & 0x0FFF) ^ r ^ CRC_16_TABLE[byte & 0x0F]
        r = CRC_16_TABLE[crc & 0x0F]
        crc = ((crc >> 4) & 0x0FFF) ^ r ^ CRC_16_TABLE[(byte >> 4) & 0x0F]
    return crc

def parse_header(file_path):
    """Parse PRODINFO header."""
    with open(file_path, "r+b") as file:
        header = file.read(0x40)
        file_size = os.path.getsize(file_path)
        if file_size == 0x3FBC00:
            file.seek(0x3FC0)
            rsa_block = file.read(0x250)
            if DEBUG_MODE:
                print(f"Rsa2048DeviceCertificateBlock (0x3FC0-0x420F): {rsa_block.hex().upper()[:64]}...")
    if DEBUG_MODE:
        print(f"Raw header (0x00-0x3F): {header.hex().upper()}")
    try:
        magic, version, body_size, model, update_count, pad, crc, body_hash = struct.unpack("<IIIHH14sH32s", header)
        if magic != 0x304C4143:
            raise ValueError("Invalid CAL0 magic")
        computed_crc = get_crc_16(header[:0x1E])
        if computed_crc != crc:
            raise ValueError(f"Header CRC-16 mismatch: computed {computed_crc:04X}, stored {crc:04X}")
        if DEBUG_MODE:
            print(f"Parsed header: magic={magic:08X}, version={version}, body_size={body_size}, model={model}, update_count={update_count}, crc={crc:04X}")
        return body_size, body_hash
    except struct.error as e:
        if DEBUG_MODE:
            print(f"Header parsing failed: {e}. Using fallback body_size 32704")
        return 32704, None

def compute_sha256(file_path, offset=0x40):
    """Compute SHA-256 using body_size from header."""
    with open(file_path, "rb") as file:
        file_size = os.path.getsize(file_path)
        try:
            body_size, _ = parse_header(file_path)
        except ValueError as e:
            if DEBUG_MODE:
                print(f"Error in compute_sha256: {e}. Using fallback body_size 32704.")
            body_size = 32704
        if body_size + offset > file_size:
            body_size = file_size - offset
        file.seek(offset)
        data = file.read(body_size)
        if len(data) != body_size:
            raise ValueError(f"Failed to read {body_size} bytes from offset 0x{offset:04X}")
        computed_hash = hashlib.sha256(data).digest()
    if DEBUG_MODE:
        print(f"Computed SHA-256 (offset 0x{offset:04X}, size={body_size} bytes): {computed_hash.hex().upper()}")
    return computed_hash

def is_valid_prodinfo(file_path):
    """Validate PRODINFO file."""
    if not os.path.exists(file_path):
        messagebox.showerror("Error", "PRODINFO file does not exist.")
        return False
    file_size = os.path.getsize(file_path)
    with open(file_path, "rb") as file:
        magic = file.read(4)
        if magic != b"CAL0":
            messagebox.showerror("Error", "Invalid PRODINFO file: Missing CAL0 magic.")
            return False
        try:
            body_size, _ = parse_header(file_path)
            if DEBUG_MODE:
                print(f"Validation passed: File size={file_size}, CAL0 magic={magic.hex()}, body_size={body_size}")
        except ValueError as e:
            if DEBUG_MODE:
                print(f"Validation warning: Failed to validate header: {e}.")
        return True

def open_prodinfo():
    """Open and validate PRODINFO file."""
    global prodinfo_file_path, region_changed
    prodinfo_file_path = filedialog.askopenfilename(title="Select PRODINFO File", filetypes=[("PRODINFO Files", "*.*")])
    if not prodinfo_file_path:
        status_label.config(text="No file selected.", bootstyle="warning")
        return
    if not is_valid_prodinfo(prodinfo_file_path):
        status_label.config(text="Invalid PRODINFO file.", bootstyle="danger")
        return
    if not os.access(prodinfo_file_path, os.W_OK):
        status_label.config(text="File is read-only.", bootstyle="warning")
        return
    # Only create backup if .bak doesn't already exist (preserves original backup)
    backup_path = prodinfo_file_path + ".bak"
    if not os.path.exists(backup_path):
        shutil.copy(prodinfo_file_path, backup_path)
    region_changed = False
    with open(prodinfo_file_path, "rb") as file:
        file.seek(0x20)
        original_hash = file.read(32)
        file.seek(0x40)
        pre_block = file.read(0x40)
        file.seek(0x80)
        block_data = file.read(0x18E)
        stored_crc = int.from_bytes(file.read(2), byteorder="little")
        computed_crc = get_crc_16(block_data)
        file.seek(0x88)
        wifi_region_data = file.read(4)
        wifi_region_hex = wifi_region_data.hex().upper()
        current_region.set(REGION_MAP.get(wifi_region_hex, "Unknown"))
        if DEBUG_MODE:
            print(f"Original SHA-256 at 0x20: {original_hash.hex().upper()}")
            print(f"Pre-block 0x40-0x7F: {pre_block.hex().upper()}")
            print(f"Block 0x80-0x20F: {block_data.hex().upper()} {stored_crc:04X}")
            print(f"Region Code at 0x88: {wifi_region_hex}")
            print(f"Stored CRC-16 (0x20E-0x20F): {stored_crc:04X}")
            print(f"Computed CRC-16: {computed_crc:04X}")
            print(f"File size: {os.path.getsize(prodinfo_file_path)} bytes")
        if stored_crc != computed_crc:
            status_label.config(text=f"CRC-16 mismatch. Stored: {stored_crc:04X}, Computed: {computed_crc:04X}", bootstyle="warning")
        else:
            status_label.config(text="PRODINFO loaded successfully.", bootstyle="success")
    update_button["state"] = "normal" if not region_changed else "disabled"
    status_label.config(text="PRODINFO loaded successfully.", bootstyle="success")

def update_wifi_region():
    """Update WiFi region code and recalculate CRC-16 and SHA-256."""
    global region_changed
    if not prodinfo_file_path:
        status_label.config(text="No file selected.", bootstyle="warning")
        return
    new_region_code = REGION_CODE_MAP.get(region_var.get())
    if not new_region_code:
        status_label.config(text="Invalid region selected.", bootstyle="warning")
        return
    with open(prodinfo_file_path, 'r+b') as file:
        file.seek(0x80)
        current_block = file.read(0x190)
        current_region = current_block[8:12]
        current_crc = int.from_bytes(current_block[0x18E:0x190], byteorder="little")
        if current_region == new_region_code:
            status_label.config(text="Wi-Fi region already set.", bootstyle="info")
            return
        block_data = bytearray(current_block[0:0x18E])
        block_data[0x08:0x0C] = new_region_code
        new_crc = get_crc_16(block_data)
        file.seek(0x80)
        file.write(block_data)
        file.write(new_crc.to_bytes(2, byteorder="little"))
        file.flush()
        try:
            body_size, _ = parse_header(prodinfo_file_path)
            new_sha256 = compute_sha256(prodinfo_file_path, offset=0x40)
            with open(prodinfo_file_path, "rb") as f:
                f.seek(0x40)
                body_data = f.read(body_size)
                expected_sha256 = hashlib.sha256(body_data).digest()
                if new_sha256 != expected_sha256:
                    if DEBUG_MODE:
                        print(f"SHA-256 verification failed: computed {new_sha256.hex().upper()}, expected {expected_sha256.hex().upper()}")
                    raise ValueError("SHA-256 verification failed")
                if DEBUG_MODE:
                    print(f"SHA-256 verification passed: {new_sha256.hex().upper()}")
        except ValueError as e:
            if DEBUG_MODE:
                print(f"Error in update_wifi_region: {e}")
            status_label.config(text=f"Failed to compute SHA-256: {e}", bootstyle="danger")
            return
        file.seek(0x20)
        file.write(new_sha256)
        file.flush()
        file.seek(0x88)
        actual_region = file.read(4)
        file.seek(0x20E)
        actual_crc = int.from_bytes(file.read(2), byteorder="little")
        computed_crc = get_crc_16(block_data)
        if file_size := os.path.getsize(prodinfo_file_path) >= 0x8000:
            file.seek(0x0)
            full_block = file.read(0x1F40)
            full_block_crc = get_crc_16(full_block)
            invalid_block = file.read(0x1F00)
            invalid_block_crc = get_crc_16(invalid_block)
            backup_block = file.read(0x8000)
            backup_block_crc = get_crc_16(backup_block)
            file.seek(0x1F40)
            checksum_1F40 = file.read(0x4)
            file.seek(0x8000)
            checksum_8000 = file.read(0x4) if file_size >= 0x8004 else b""
            file.seek(0x1F3C)
            checksum_1F3C = file.read(0x4)
            if DEBUG_MODE:
                print(f"Full block (0x0-0x1F3F): CRC-16: {full_block_crc:04X}")
                print(f"Invalid block (0x40-0x1F3F): CRC-16: {invalid_block_crc:04X}")
                print(f"Backup block (0x0-0x7FFF): CRC-16: {backup_block_crc:04X}")
                print(f"Stored checksum at 0x1F40-0x1F43: {checksum_1F40.hex().upper()}")
                print(f"Checksum at 0x8000-0x8003: {checksum_8000.hex().upper()}")
                print(f"Checksum at 0x1F3C-0x1F3F: {checksum_1F3C.hex().upper()}")
        if DEBUG_MODE:
            file.seek(0x40)
            pre_block = file.read(0x40)
            file.seek(0x80)
            updated_block = file.read(0x18E)
            print(f"New SHA-256 at 0x20: {new_sha256.hex().upper()}")
            print(f"Pre-block 0x40-0x7F: {pre_block.hex().upper()}")
            print(f"Updated Block 0x80-0x20F: {updated_block.hex().upper()} {actual_crc:04X}")
            print(f"Updated Region Code: {actual_region.hex().upper()}")
            print(f"New CRC-16: {actual_crc:04X}")
            print(f"Computed CRC-16: {computed_crc:04X}")
            print(f"File size: {os.path.getsize(prodinfo_file_path)} bytes")
        if actual_region != new_region_code or actual_crc != new_crc:
            status_label.config(text="Region code or CRC-16 mismatch.", bootstyle="danger")
        else:
            status_label.config(text="Wi-Fi region updated successfully!", bootstyle="success")
            region_changed = True
            update_button["state"] = "disabled"
            region_dropdown["state"] = "disabled"

# GUI Setup
root = ttk.Window(themename="darkly")
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
if screen_width >= 3840 and screen_height >= 2160:
    WINDOW_WIDTH, WINDOW_HEIGHT = 580, 220
elif screen_width >= 1920 and screen_height >= 1080:
    WINDOW_WIDTH, WINDOW_HEIGHT = 380, 160
else:
    WINDOW_WIDTH, WINDOW_HEIGHT = 480, 180
root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
root.title("NX WiFi Region Changer v1.0.2")
root.resizable(False, False)
icon_path_png = resource_path("wifi.png")
icon_path_ico = resource_path("wifi.ico")
try:
    img = PhotoImage(file=icon_path_png)
    root.iconphoto(True, img)
    if platform.system() == "Windows":
        root.iconbitmap(icon_path_ico)
except Exception as e:
    print(f"Error loading icon: {e}")
common_width = 24
current_region = ttk.StringVar(value="Unknown")
region_changed = False
ttk.Label(root, text="Current Region:", bootstyle="light").grid(row=0, column=0, padx=10, pady=5, sticky="w")
ttk.Label(root, textvariable=current_region, font=("Arial", 10, "bold"), bootstyle="light").grid(row=0, column=1, padx=10, pady=5, sticky="w")
ttk.Label(root, text="Select New Region:", bootstyle="light").grid(row=1, column=0, padx=10, pady=5, sticky="w")
region_var = ttk.StringVar()
region_dropdown = ttk.Combobox(root, textvariable=region_var, values=list(REGION_CODE_MAP.keys()), state="readonly", width=common_width)
region_dropdown.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
open_button = ttk.Button(root, text="Open PRODINFO", command=open_prodinfo, bootstyle="primary", width=common_width)
open_button.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
update_button = ttk.Button(root, text="Update Region", command=update_wifi_region, bootstyle="success", state="disabled", width=common_width)
update_button.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
status_label = ttk.Label(root, text="Status: Ready", bootstyle="light", wraplength=WINDOW_WIDTH - 30)
status_label.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
root.mainloop()