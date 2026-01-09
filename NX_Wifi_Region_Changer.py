import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, PhotoImage, messagebox, scrolledtext
import hashlib
import os
import shutil
import sys
import platform
import ctypes
import struct

# Set DPI awareness for high-resolution scaling on Windows
if platform.system() == "Windows":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except AttributeError:
        pass

# Determine the script's directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def resource_path(relative_path):
    """Get the absolute path to a resource, handling PyInstaller's temp folder."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = SCRIPT_DIR
    return os.path.join(base_path, relative_path)

def check_icon_files():
    """Check if wifi.ico and wifi.png are in the correct directory."""
    wifi_ico_path = resource_path("wifi.ico")
    wifi_png_path = resource_path("wifi.png")

    if not os.path.exists(wifi_ico_path):
        messagebox.showwarning("Warning", f"wifi.ico not found. Using default icon.")
    if not os.path.exists(wifi_png_path):
        messagebox.showwarning("Warning", f"wifi.png not found. Using default icon.")

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

def calculate_crc16(data):
    """Calculate CRC16 using lookup table - matches NAND Fix Pro implementation"""
    crc = 0x55AA
    for byte in data:
        r = CRC_16_TABLE[crc & 0x0F]
        crc = ((crc >> 4) & 0x0FFF) ^ r ^ CRC_16_TABLE[byte & 0x0F]
        r = CRC_16_TABLE[crc & 0x0F]
        crc = ((crc >> 4) & 0x0FFF) ^ r ^ CRC_16_TABLE[(byte >> 4) & 0x0F]
    return crc & 0xFFFF

def compute_sha256(file_path, offset=0x40):
    """Compute SHA256 hash of PRODINFO body using EXACT body size from header"""
    with open(file_path, "rb") as file:
        # Read body size from header (offset 0x8, 4 bytes, little endian)
        file.seek(0x8)
        body_size = struct.unpack('<I', file.read(4))[0]
        
        # Validate body size to prevent reading beyond file
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        max_possible_size = file_size - offset
        
        if body_size > max_possible_size:
            body_size = max_possible_size
        
        # Hash EXACTLY body_size bytes starting from offset
        file.seek(offset)
        body_data = file.read(body_size)
        computed_hash = hashlib.sha256(body_data).digest()
        
    return computed_hash, body_size

def is_valid_prodinfo(file_path):
    if not os.path.exists(file_path):
        return False
    file_size = os.path.getsize(file_path)
    if file_size not in [0x40000, 0x3FBC00]:  # 262,144 or 4,176,896 bytes
        return False
    with open(file_path, "rb") as file:
        return file.read(4) == b"CAL0"

def verify_prodinfo_integrity(file_path):
    """Verify the integrity of the PRODINFO file"""
    verification_results = []
    
    try:
        with open(file_path, "rb") as file:
            # Read critical header values
            file.seek(0x8)
            body_size = struct.unpack('<I', file.read(4))[0]
            verification_results.append(f"Header body_size: {body_size} bytes (0x{body_size:X})")
            verification_results.append(f"File size: {os.path.getsize(file_path)} bytes (0x{os.path.getsize(file_path):X})")
            
            # 1. Verify header CRC16
            file.seek(0)
            header_data = file.read(0x1E)
            file.seek(0x1E)
            stored_header_crc = struct.unpack('<H', file.read(2))[0]
            computed_header_crc = calculate_crc16(header_data)
            
            if stored_header_crc == computed_header_crc:
                verification_results.append("✓ Header CRC16: VALID")
            else:
                verification_results.append(f"✗ Header CRC16: INVALID (stored: {stored_header_crc:04X}, computed: {computed_header_crc:04X})")
            
            # 2. Verify body SHA256 with EXACT size calculation
            file.seek(0x20)
            stored_body_hash = file.read(32)
            computed_body_hash, hashed_size = compute_sha256(file_path, 0x40)
            
            if stored_body_hash == computed_body_hash:
                verification_results.append("✓ Body SHA256: VALID")
                verification_results.append(f"  Hashed range: 0x40 to 0x{0x40 + hashed_size:X} ({hashed_size} bytes)")
            else:
                verification_results.append(f"✗ Body SHA256: INVALID")
                verification_results.append(f"  Hashed range: 0x40 to 0x{0x40 + hashed_size:X} ({hashed_size} bytes)")
                verification_results.append(f"  Stored:   {stored_body_hash.hex().upper()}")
                verification_results.append(f"  Computed: {computed_body_hash.hex().upper()}")
                verification_results.append("  This will cause Atmosphère to flag as INVALID_PRODINFO!")
            
            # 3. Verify WlanCountryCodes block CRC16
            file.seek(0x80)
            block_data = file.read(0x18E)
            file.seek(0x20E)
            stored_crc = struct.unpack('<H', file.read(2))[0]
            computed_crc = calculate_crc16(block_data)
            
            if stored_crc == computed_crc:
                verification_results.append("✓ WlanCountryCodes CRC16: VALID")
            else:
                verification_results.append(f"✗ WlanCountryCodes CRC16: INVALID (stored: {stored_crc:04X}, computed: {computed_crc:04X})")
            
            # Count errors
            error_count = sum(1 for result in verification_results if result.startswith("✗"))
            
            if error_count == 0:
                return True, "\n".join(verification_results)
            else:
                return False, f"Found {error_count} critical errors:\n" + "\n".join(verification_results)
                
    except Exception as e:
        return False, f"Verification failed: {e}"

def log_message(message):
    """Add a message to the log widget"""
    log_widget.config(state="normal")
    log_widget.insert("end", message + "\n")
    log_widget.see("end")
    log_widget.config(state="disabled")

def clear_log():
    """Clear the log widget"""
    log_widget.config(state="normal")
    log_widget.delete("1.0", "end")
    log_widget.config(state="disabled")

def save_log():
    """Save the current log contents to a file"""
    try:
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"nx_wifi_region_log_{timestamp}.txt"
        
        file_path = filedialog.asksaveasfilename(
            title="Save Log File",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=default_filename
        )
        
        if file_path:
            log_content = log_widget.get("1.0", "end")
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"NX WiFi Region Changer v1.1.0 - Log Export\n")
                f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*50 + "\n\n")
                f.write(log_content)
            
            log_message(f"Log saved to: {file_path}")
            status_label.config(text="Log saved successfully.", bootstyle="success")
            
    except Exception as e:
        messagebox.showerror("Save Error", f"Failed to save log file:\n\n{e}")

def reset_app():
    """Reset the application to initial state"""
    global prodinfo_file_path, region_changed
    
    result = messagebox.askyesno("Confirm Reset", 
                                 "Are you sure you want to reset the application?\n\n"
                                 "This will clear the log and reset all settings.")
    if not result:
        return
    
    # Reset variables
    prodinfo_file_path = None
    region_changed = False
    current_region.set("Unknown")
    region_var.set("")
    
    # Disable buttons
    update_button["state"] = "disabled"
    verify_button["state"] = "disabled"
    region_dropdown["state"] = "readonly"
    
    # Clear and reset log
    clear_log()
    log_message("Application reset. Ready for new operation.")
    
    # Reset status
    status_label.config(text="Status: Ready", bootstyle="light")

def show_verification():
    """Run verification and display results in log"""
    if not prodinfo_file_path:
        messagebox.showwarning("Warning", "No file selected. Please open a PRODINFO file first.")
        return
    
    clear_log()
    log_message("=== PRODINFO Integrity Verification ===\n")
    
    is_valid, results = verify_prodinfo_integrity(prodinfo_file_path)
    
    if is_valid:
        log_message("✓ VERIFICATION PASSED\n")
    else:
        log_message("✗ VERIFICATION FAILED\n")
    
    log_message(results)
    log_message("\n" + "="*50)

def open_prodinfo():
    global prodinfo_file_path, region_changed
    prodinfo_file_path = filedialog.askopenfilename(title="Select PRODINFO File", 
                                                     filetypes=[("PRODINFO Files", "*.*")])
    if not prodinfo_file_path:
        status_label.config(text="No file selected. Please open a PRODINFO file.", bootstyle="warning")
        return

    if not is_valid_prodinfo(prodinfo_file_path):
        status_label.config(text="Invalid PRODINFO file size or format.", bootstyle="danger")
        clear_log()
        log_message("✗ ERROR: Invalid PRODINFO file size or format.")
        return

    if not os.access(prodinfo_file_path, os.W_OK):
        status_label.config(text="File is read-only. Please check permissions.", bootstyle="warning")
        clear_log()
        log_message("⚠ WARNING: File is read-only. Please check permissions.")
        return

    # Only create backup if .bak doesn't already exist (preserves original backup)
    backup_path = prodinfo_file_path + ".bak"
    if not os.path.exists(backup_path):
        shutil.copy(prodinfo_file_path, backup_path)
        log_message(f"✓ Backup created: {os.path.basename(backup_path)}")
    else:
        log_message(f"⚠ Backup already exists, preserving original: {os.path.basename(backup_path)}")

    region_changed = False

    with open(prodinfo_file_path, "rb") as file:
        file.seek(0x88)
        wifi_region_data = file.read(4)
        wifi_region_hex = wifi_region_data.hex().upper()
        current_region.set(REGION_MAP.get(wifi_region_hex, "Unknown"))

    update_button["state"] = "normal"
    verify_button["state"] = "normal"
    status_label.config(text="PRODINFO file loaded successfully.", bootstyle="success")
    
    clear_log()
    log_message(f"✓ PRODINFO file loaded: {os.path.basename(prodinfo_file_path)}")
    log_message(f"Current WiFi Region: {current_region.get()}")

def update_wifi_region():
    global region_changed
    if not prodinfo_file_path:
        status_label.config(text="No file selected. Please open a PRODINFO file.", bootstyle="warning")
        return

    new_region_code = REGION_CODE_MAP.get(region_var.get())
    if not new_region_code:
        status_label.config(text="Invalid region selected. Please choose a valid Wi-Fi region.", bootstyle="warning")
        return

    with open(prodinfo_file_path, 'r+b') as file:
        # Read current block data
        file.seek(0x80)
        block_data = bytearray(file.read(0x18E))
        current_region_bytes = block_data[8:12]

        if current_region_bytes == new_region_code:
            status_label.config(text="Wi-Fi region is already set to the selected value.", bootstyle="info")
            log_message("⚠ Region is already set to the selected value.")
            return

        clear_log()
        log_message("=== Updating WiFi Region ===\n")
        log_message(f"Previous Region: {REGION_MAP.get(current_region_bytes.hex().upper(), 'Unknown')}")
        log_message(f"New Region: {region_var.get()}\n")

        # Update region code
        block_data[0x08:0x0C] = new_region_code
        new_crc = calculate_crc16(block_data)

        # Write updated block and CRC-16
        file.seek(0x80)
        file.write(block_data)
        file.write(new_crc.to_bytes(2, byteorder="little"))
        log_message(f"✓ Updated WlanCountryCodes block")
        log_message(f"✓ New CRC16: {new_crc:04X}")

        # Update header update count
        file.seek(0x10)
        update_count = struct.unpack('<H', file.read(2))[0]
        update_count += 1
        file.seek(0x10)
        file.write(struct.pack('<H', update_count))
        log_message(f"✓ Incremented update counter to: {update_count}")

        # Update header CRC
        file.seek(0)
        header_data = file.read(0x1E)
        header_crc = calculate_crc16(header_data)
        file.seek(0x1E)
        file.write(struct.pack('<H', header_crc))
        log_message(f"✓ Updated header CRC16: {header_crc:04X}")

        # Recalculate and update SHA-256
        new_sha256, _ = compute_sha256(prodinfo_file_path, 0x40)
        file.seek(0x20)
        file.write(new_sha256)
        log_message(f"✓ Updated body SHA256: {new_sha256.hex().upper()[:32]}...")

    log_message("\n✓ WiFi region updated successfully!")
    log_message("="*50)
    status_label.config(text="Wi-Fi region updated successfully!", bootstyle="success")
    region_changed = True
    update_button["state"] = "disabled"
    region_dropdown["state"] = "disabled"

# Create the main window
root = ttk.Window(themename="darkly")

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

if screen_width >= 3840 and screen_height >= 2160:
    WINDOW_WIDTH, WINDOW_HEIGHT = 590, 830
elif screen_width >= 1920 and screen_height >= 1080:
    WINDOW_WIDTH, WINDOW_HEIGHT = 600, 500
else:
    WINDOW_WIDTH, WINDOW_HEIGHT = 650, 550

root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
root.title("NX WiFi Region Changer v1.1.0")
root.resizable(True, True)

# Set the window icon
icon_path_png = resource_path("wifi.png")
icon_path_ico = resource_path("wifi.ico")

try:
    img = PhotoImage(file=icon_path_png)
    root.iconphoto(True, img)
    if platform.system() == "Windows":
        root.iconbitmap(icon_path_ico)
except Exception as e:
    pass

# GUI Layout
current_region = ttk.StringVar(value="Unknown")
region_changed = False
prodinfo_file_path = None

# Top frame for controls
control_frame = ttk.Frame(root, padding=10)
control_frame.pack(fill="x", padx=10, pady=10)

ttk.Label(control_frame, text="Current Region:", bootstyle="light").grid(row=0, column=0, padx=10, pady=5, sticky="w")
ttk.Label(control_frame, textvariable=current_region, font=("Arial", 10, "bold"), bootstyle="light").grid(row=0, column=1, padx=10, pady=5, sticky="w")
ttk.Label(control_frame, text="Select New Region:", bootstyle="light").grid(row=1, column=0, padx=10, pady=5, sticky="w")

region_var = ttk.StringVar()
region_dropdown = ttk.Combobox(control_frame, textvariable=region_var, values=list(REGION_CODE_MAP.keys()), 
                               state="readonly", width=24)
region_dropdown.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

# Button frame
button_frame = ttk.Frame(control_frame)
button_frame.grid(row=2, column=0, columnspan=2, pady=10)

open_button = ttk.Button(button_frame, text="Open PRODINFO", command=open_prodinfo, 
                        bootstyle="primary", width=15)
open_button.pack(side="left", padx=5)

update_button = ttk.Button(button_frame, text="Update Region", command=update_wifi_region, 
                          bootstyle="success", state="disabled", width=15)
update_button.pack(side="left", padx=5)

verify_button = ttk.Button(button_frame, text="Verify Integrity", command=show_verification,
                          bootstyle="info", state="disabled", width=15)
verify_button.pack(side="left", padx=5)

# Status label
status_label = ttk.Label(control_frame, text="Status: Ready", bootstyle="light", wraplength=WINDOW_WIDTH - 50)
status_label.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

# Log frame
log_frame = ttk.LabelFrame(root, text="Log Output", padding=10)
log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

# Log widget
log_widget = scrolledtext.ScrolledText(log_frame, wrap="word", height=15, state="disabled",
                                       font=("Consolas", 9))
log_widget.pack(fill="both", expand=True)

# Button frame at bottom right of log
log_button_frame = ttk.Frame(log_frame)
log_button_frame.pack(fill="x", pady=(5, 0))

# Spacer to push buttons to the right
ttk.Frame(log_button_frame).pack(side="left", fill="x", expand=True)

# Buttons aligned to the right
reset_button = ttk.Button(log_button_frame, text="Reset App", command=reset_app, 
                         bootstyle="secondary", width=12)
reset_button.pack(side="left", padx=(0, 5))

clear_log_button = ttk.Button(log_button_frame, text="Clear Log", command=clear_log, 
                         bootstyle="secondary", width=12)
clear_log_button.pack(side="left", padx=(0, 5))

save_log_button = ttk.Button(log_button_frame, text="Save Log", command=save_log, 
                            bootstyle="secondary", width=12)
save_log_button.pack(side="left")

root.mainloop()