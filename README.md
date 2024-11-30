# FRECE: File Recovery Enhanced Command-line Environment (README)

## Overview

**FRECE** (File Recovery Enhanced Command-line Environment) is a powerful, Python-based tool for recovering lost files, integrating with tools like **TestDisk** and **PhotoRec**. Designed for use on **Kali Linux** and other Linux distributions, FRECE provides an interactive command-line interface with color-coded outputs and file system navigation via tab completion.

The tool offers functionality for scanning directories, recovering files, running TestDisk/PhotoRec, and listing file types, all while providing helpful, dynamic banners for a friendly user experience.

---

## Features

- **File Recovery:** Recover files from specified directories.
- **Directory Scanning:** Scan directories for specific file types using extensions.
- **Automated Tools:** Integrates with TestDisk and PhotoRec for advanced recovery.
- **Tab Autocomplete:** Autocompletion of file paths and commands, similar to Kali Linux.
- **Interactive Mode:** Engaging CLI with help and command manuals.

---

## Prerequisites

Before installing FRECE, ensure your system meets the following requirements:

1. **Kali Linux** or a Linux-based OS.
2. **Python 3.x** installed.
3. **Git** installed for repository management.
4. **TestDisk** and **PhotoRec** available (auto-installed during setup).
5. **Colorama** Python library (installed automatically in a virtual environment).

---

## Installation Instructions

The provided `install.sh` script automates the installation process. Follow the steps below:

### Step 1: Clone and Run the Installer

```bash
chmod +x install.sh
sudo ./install.sh
```

### Step 2: Verify Installation

Once the installation is complete, activate the virtual environment and check the version:

```bash
source ~/frece_venv/bin/activate
frece --version
```

To get help on available commands, run:

```bash
frece --help
```

---

## Usage

### Running FRECE

FRECE can be used interactively or with command-line arguments. Start the interactive mode by running:

```bash
frece
```

You will see a banner and can enter commands such as `recover`, `scan`, `list`, etc.

### Command Overview

| Command                              | Description                                                 |
|--------------------------------------|-------------------------------------------------------------|
| `recover <source_dir> <target_dir>`  | Recover files from source to target directory.              |
| `scan <directory> [extension]`       | Scan directory for files, filter by extension if specified. |
| `list <directory>`                   | List file types and their counts in the specified directory.|
| `testdisk`                           | Run TestDisk for partition/file recovery.                   |
| `photorec`                           | Run PhotoRec to recover files by signature.                 |
| `save <directory>`                   | Save recovered files to a specified directory.              |
| `man <command>`                      | Display manual for a specific command.                      |
| `--version`                          | Display the tool version.                                   |
| `--help`                             | Display available commands and usage.                       |
| `exit`                               | Exit the interactive mode.                                  |

---

## Updating FRECE

To update FRECE to the latest version:

```bash
sudo ./install.sh --update
```
if any problem occured while updateing saying " To add an exception for this directory, call:

        git config --global --add safe.directory /path/to/frece
Failed to pull updates. Please check your network connection. " Then use the below command and then try to update it.
```bash
sudo git config --global --add safe.directory /path/to/frece./install.sh 
sudo ./install.sh --update
``` 


This will pull the latest changes from the repository and replace the existing script.

---

## Uninstallation

To uninstall FRECE, remove the installed files and the virtual environment:

```bash
sudo rm /usr/local/bin/frece
rm -rf ~/frece_venv
```

---

## License and Contributions

This project is open-source and contributions are welcome. If you encounter issues or have suggestions, feel free to open an issue on the [GitHub repository](https://github.com/Nakum-hub/frece).

---

## Troubleshooting

- **Permission Errors:** Ensure you run commands with `sudo` if necessary.
- **Dependency Issues:** Verify that TestDisk, PhotoRec, and Python dependencies are installed correctly.
- **Git Issues:** Ensure you have network connectivity when using `--update`.

---

### Author
Created by **Nakum-hub** for efficient and enhanced file recovery.