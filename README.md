# NX WiFi Region Changer

NX WiFi Region Changer is a simple tool for updating the Wi-Fi region in your NX PRODINFO file while ensuring data integrity.

## Features

- **Easy to Use:** Graphical interface with simple controls.
- **Cross-Platform:** Works on Windows (EXE) and macOS/Linux (Python script).
- **File Validation:** Ensures the file format is correct.
- **Region Update:** Supports Americas, Asia, Australia, Europe, Japan, and Malaysia.
- **Automatic Backup:** Creates a `.bak` file before making changes.
- **Error Handling:** Displays clear messages for issues.

## Requirements

- **Windows:** EXE version runs without extra setup.
- **macOS/Linux:** Requires Python 3.6+ and `ttkbootstrap`:
  ```bash
  pip install ttkbootstrap
  ```
- Ensure `wifi.ico` and `wifi.png` are in the same directory.

## Installation

### Windows (EXE)
Just run the NX WiFi Region Changer executable.

### macOS/Linux (Python)
1. Download the script.
2. Install dependencies:
   ```bash
   pip install ttkbootstrap
   ```
3. Run:
   ```bash
   python nx_wifi_region_changer.py
   ```

## Usage

1. Open the app.
2. Select a decrypted PRODINFO file.
3. Choose a new region.
4. Click **Update Region**.
5. A backup is created automatically.

## Troubleshooting

- **Missing Icons:** Ensure `wifi.ico` and `wifi.png` are in the same folder.
- **Invalid File:** Ensure the correct PRODINFO file is selected.
- **Checksum Error:** Indicates possible file corruption.

## License

This project is under the [MIT License](LICENSE).

## Credits

Developed by **sthetix**. Special thanks to [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap).

This project is based on the written guide from [r/SwitchPirates](https://www.reddit.com/r/SwitchPirates/comments/1avooiv/guide_changing_wifi_regions_on_any_switch_console/).

