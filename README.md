# FRECE - File Recovery Console (FRECE)

FRECE (File Recovery Console) is a tool designed to recover and analyze deleted files from various file systems. This tool provides functionalities for scanning directories, recovering files, and creating detailed recovery reports.

---

## Features

- **Recover Files**: Recover files from specified directories or from the recycle bin.
- **Scan Directories**: Scan a directory for files, optionally filter by file extension.
- **Search Deleted Files**: Search for deleted files within a directory (feature in development).
- **Generate Recovery Reports**: Generate detailed recovery reports for analysis.
- **View Files**: View the contents of recovered files.
- **Disk Imaging and Carving**: Create forensic-quality images of disks and carve files from disk images.

---



### Prerequisites

- **Python 3.6+**
- **Git** (for cloning the repository)
- **Linux** (Tested on Kali Linux, but should work on other distributions)

### Installing FRECE

To install FRECE globally on your system, follow these steps:

1. Clone the repository:
   
   ```bash
   git clone https://github.com/Nakum-hub/frece.git
   cd frece



### Overview
The `install.sh` script automates the installation of the **FRECE** tool, a Python-based forensic recovery tool, by cloning the tool's repository directly into the `/usr/local/bin` directory. Once installed, the tool can be accessed globally from anywhere on the system using the command `frece`.

---

### Features of the Installation Script
1. **Direct Installation to `/usr/local/bin`:**
   - The script ensures the tool is installed directly in the `/usr/local/bin` directory for universal accessibility.
   
2. **Repository Management:**
   - Clones the FRECE GitHub repository.
   - Extracts only the necessary `frece.py` script for execution.

3. **Clean Installation:**
   - Ensures no temporary directories like `/tmp` are used.
   - Removes unnecessary files after setup.

4. **Error Handling:**
   - Prevents overwriting if the tool is already installed.
   - Exits gracefully if cloning fails.

---

### Requirements
1. **Root Privileges:**
   - The script requires `sudo` or `root` access to write to the `/usr/local/bin` directory.

2. **Git Installed:**
   - Ensure `git` is installed on your system:
     ```bash
     sudo apt update && sudo apt install git
     ```

3. **Python Installed:**
   - FRECE requires Python to execute. Install Python if not already available:
     ```bash
     sudo apt install python3
     ```

---

### Installation Steps
1. **Download the Script:**
   Save the `install.sh` script to your system.

2. **Make the Script Executable:**
   Run the following command to give the script execution permissions:
   ```bash
   chmod +x install.sh
   ```

3. **Run the Script:**
   Execute the script with root privileges to begin the installation:
   ```bash
   sudo ./install.sh
   ```

4. **Verify Installation:**
   After successful installation, you can run the tool from anywhere using:
   ```bash
   frece
   ```

---

### Script Workflow
1. **Clone Repository:**
   - Downloads the FRECE repository from GitHub directly to `/usr/local/bin/frece-repo`.

2. **Install the Script:**
   - Moves the main Python script (`frece.py`) to `/usr/local/bin/frece`.

3. **Make Executable:**
   - Marks the script as executable for system-wide usage.

4. **Clean-Up:**
   - Deletes the temporary repository directory.

---

### Notes
- If the tool is already installed, the script will stop and display:
  ```
  Tool already installed at /usr/local/bin/frece
  ```
  To reinstall, manually remove the existing installation:
  ```bash
  sudo rm /usr/local/bin/frece
  ```

- The tool is designed for use on Unix-based systems (Linux or macOS).

---

### Troubleshooting
- **Error: `Command not found`**
  - Ensure `/usr/local/bin` is included in your system's `PATH`. Add it if missing:
    ```bash
    export PATH=$PATH:/usr/local/bin
    ```
  
- **Git Clone Fails:**
  - Verify your internet connection and that the repository URL is correct:
    ```bash
    https://github.com/Nakum-hub/frece.git
    ```

---

### Uninstallation
To remove FRECE, delete the script from `/usr/local/bin`:
```bash
sudo rm /usr/local/bin/frece
```

---

### Contribution
Feel free to contribute to the FRECE project by submitting issues or pull requests to the repository:
[https://github.com/Nakum-hub/frece](https://github.com/Nakum-hub/frece)

---

### License
This installation script and the FRECE tool are licensed under the terms provided in the [FRECE GitHub Repository](https://github.com/Nakum-hub/frece). Please review the license before use.

---

### Contact
For any issues or feature requests, feel free to contact the FRECE development team via GitHub or email.