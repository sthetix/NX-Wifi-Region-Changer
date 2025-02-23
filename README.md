# NX WiFi Region Changer

<p align="center" width="100%">
    <img width="450px" src="https://github.com/sthetix/NX-Wifi-Region-Changer/blob/main/app.png" alt="NX WiFi Region Changer GUI">
</p>

NX WiFi Region Changer is a simple tool for updating the Wi-Fi region in your Nintendo Switch PRODINFO file while ensuring data integrity.

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

Ensure `wifi.ico` and `wifi.png` are in the same directory as the script or executable.

## Installation

### Windows (EXE)
1. Download the `NX_WiFi_Region_Changer.exe` file.
2. Run the executable.

### macOS/Linux (Python)
1. Download the script (`nx_wifi_region_changer.py`).
2. Install dependencies:
   ```bash
   pip install ttkbootstrap
   ```
3. Run the script:
   ```bash
   python nx_wifi_region_changer.py
   ```

## Usage

Before using this tool, you need to obtain a decrypted PRODINFO file from your Nintendo Switch, modify its Wi-Fi region, and restore it to your console. Follow these detailed steps carefully to extract, decrypt, modify, and restore the PRODINFO file safely:

## Step-by-Step Guide to Modifying the Wi-Fi Region on Your Modded Nintendo Switch

### 1. Make Sure the Console is Modded
Ensure your Nintendo Switch is **modded**, whether **softmodded** or **hardmodded**, to access the necessary tools for this process.

### 2. Acquire the Required CFW Tools
Download a complete **CFW pack** like **HATS**, which includes preconfigured payloads, or manually install essential tools such as **Lockpick_RCM** and **TegraExplorer** from trusted homebrew repositories like **GitHub**. These tools are necessary for extracting encryption keys and system partitions from your Switch.

### 3. Dump Encryption Keys Using Lockpick_RCM
- If using the **HATS pack**, your console will automatically boot into **Hekate** on first startup.
- In **Hekate**, go to **Payloads**, select **Lockpick_RCM**, and launch it.
- Choose **Dump from SysNAND** to extract encryption keys.
- The **`prod.keys`** file, along with other encryption keys, will be saved on your **SD card** (usually in `/switch/`).

### 4. Extract the PRODINFO Partition Using TegraExplorer
- In **Hekate**, navigate to **Payloads**, select **TegraExplorer**, and launch it.
- Go to **Browse EMMC**, locate the **PRODINFO** partition, and dump it.
- The decrypted **`PRODINFO`** file will be saved in `/TegraExplorer/Dumps/` on your **SD card**.

### 5. Return to Hekate
- In **TegraExplorer**, select **Reboot to bootloader/update.bin** to return to **Hekate**.

### 6. Mount Your SD Card via USB
- In **Hekate**, go to **Tools** > **USB Tools** > **SD Card**.
- Connect your Switch to your **computer** via USB to mount the SD card as a drive.

### 7. Backup the PRODINFO File
- Open the **mounted SD card** on your computer.
- Navigate to `/TegraExplorer/Dumps/` and locate **`PRODINFO`**.
- Copy this file to a **safe location** on your PC as a backup in case anything goes wrong.

### 8. Modify the Wi-Fi Region Using NX WiFi Region Changer
- Download **NX_WiFi_Region_Changer.exe** (Windows) or run:
  ```bash
  python nx_wifi_region_changer.py
  ```
  (Mac/Linux).
- Open the tool and click **Open PRODINFO**, selecting the dumped `PRODINFO` file.
- Verify the **current Wi-Fi region** displayed.
- Select your **desired region** (e.g., Americas, Europe, Japan).
- Click **Update Region** to apply the changes.
- A backup of the original file will be automatically created as **`Prodinfo.bak`**.

### 9. Configure NxNandManager for Encryption
- Download and launch **NxNandManager**.
- Go to **Options** > **Configure Keyset** > **Import Keys from File**.
- Select the **`prod.keys`** file from the **SD card’s `/switch/` folder** and save the configuration.

### 10. Encrypt the Modified PRODINFO File
- In **NxNandManager**, open the modified **`PRODINFO`** file.
- Right-click it and select **Encrypt & Dump to File**.
- Save the encrypted file as **`prodinfo.enc`**.

### 11. Safely Unmount the SD Card
- **Eject the SD card** from your computer properly to prevent data corruption.

### 12. Prepare for PRODINFO Restoration in Hekate
- In **Hekate**, go to **Tools** > **USB Tools** and **disable Read-Only mode**.
- Choose **emmc RAW GPP** if modifying the **system NAND**, or **emuRAWGPP** if updating the **EmuMMC**.

### 13. Restore the Encrypted PRODINFO Using NxNandManager
- In **NxNandManager**, go to **File** > **Open Drive** and select the appropriate partition (`emmc RAW GPP` or `emuRAWGPP`).
- Right-click **PRODINFO**, select **Restore from File**, and choose **`prodinfo.enc`**.
- This will overwrite the **PRODINFO** partition with your modified file.

## Final Step: Reboot and Verify
Once completed, **reboot your Nintendo Switch** and verify that the **new Wi-Fi region settings** have been successfully applied.

## Important Notes
- **Backup Everything:** Always maintain backups of your NAND, PRODINFO file, and `prod.keys` before proceeding.
- **Use at Your Own Risk:** Modifying system files can render your Nintendo Switch inoperable if performed incorrectly.
- **Stable CFW Setup:** Ensure you have a stable CFW setup and the necessary tools installed.

## License
This project is under the **MIT License**.

## Credits
This project is inspired by the written guide from **r/SwitchPirates**: [Changing Wi-Fi Regions on Any Switch Console](https://www.reddit.com/r/SwitchPirates/comments/1avooiv/guide_changing_wifi_regions_on_any_switch_console/).
