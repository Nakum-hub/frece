# **FRECE: File Recovery Tool **

FRECE (File Recovery Enhanced Command-line Environment) is a powerful Python-based tool designed for file recovery. By integrating with tools like **TestDisk** and **PhotoRec**, it provides an interactive, color-coded CLI for recovering lost files and directories. This tool is specifically designed for **Kali Linux** and other Linux distributions, featuring tab-completion for navigation and command execution.

---

## **Overview**
**FRECE** is a tool designed to make file recovery and data recovery tasks easy and efficient. The tool offers functionality for scanning directories, recovering files, running **TestDisk**/ **PhotoRec**, listing file types, and providing dynamic help in an interactive mode.

---

## **Features**
- **File Recovery:** Recover deleted or lost files from specified directories.
- **Directory Scanning:** Scan directories for specific file types using extensions.
- **Automated Tools:** Integrates with **TestDisk** and **PhotoRec** for advanced recovery.
- **Tab Autocomplete:** Tab completion for file paths and commands, similar to Kali Linux.
- **Interactive Mode:** CLI with command manuals and dynamic help.
- **Color-coded Output:** Uses **Colorama** to add color to terminal outputs, enhancing user experience.

---

## **Prerequisites**
Before installing FRECE, ensure your system meets the following requirements:

1. **Kali Linux** or another Linux-based operating system.
2. **Python 3.x** installed.
3. **Git** installed for cloning the repository.
4. **TestDisk** and **PhotoRec** installed (these are auto-installed during setup).
5. **Colorama** Python library (automatically installed in the virtual environment).

---

## **Installation Instructions**
The provided `install.sh` script automates the entire installation process. Follow these steps:

### Step 1: Clone and Run the Installer

First, clone the repository and change to the project directory:
```bash
git clone https://github.com/Nakum-hub/frece.git
cd frece
```

Next, make the installation script executable and run it:
```bash
chmod +x install.sh
sudo ./install.sh
```

### Step 2: Verify Installation

Once the installation is complete, activate the virtual environment and verify the installation:
```bash
source ~/frece_venv/bin/activate
frece --version
```

To see a list of available commands, run:
```bash
frece --help
```

---

## **Usage**

FRECE can be run interactively or with command-line arguments.

### Interactive Mode
To start the interactive mode, simply type:
```bash
frece
```

In this mode, you can execute commands such as:
- `recover`
- `scan`
- `list`
- `save`
- `man`

You will also see a dynamic banner and can navigate the filesystem easily using tab completion.

### Command Overview

| Command                              | Description                                                 |
|--------------------------------------|-------------------------------------------------------------|
| `recover <source_dir> <target_dir>`  | Recover files from source to target directory.              |
| `scan <directory> [extension]`       | Scan directory for files and filter by extension if given.  |
| `list <directory>`                   | List file types and their counts in the specified directory.|
| `testdisk`                           | Run TestDisk for partition/file recovery.                   |
| `photorec`                           | Run PhotoRec to recover files by signature.                 |
| `save <directory>`                   | Save recovered files to the specified directory.            |
| `man <command>`                      | Display manual for a specific command.                      |
| `--version`                          | Display the tool version.                                   |
| `--help`                             | Display available commands and usage.                       |
| `exit`                               | Exit interactive mode.                                      |

---

## **Updating FRECE**
To update FRECE to the latest version, use the following command:
```bash
sudo ./install.sh --update
```

If you encounter an issue with Git and receive the message:
```
To add an exception for this directory, call:
    git config --global --add safe.directory /path/to/frece
Failed to pull updates. Please check your network connection.
```

Resolve it by running:
```bash
sudo git config --global --add safe.directory /path/to/frece
sudo ./install.sh --update
```

---

## **Uninstallation**
To uninstall FRECE and remove all installed files and the virtual environment:
```bash
sudo rm /usr/local/bin/frece
rm -rf ~/frece_venv
```

---

## **Troubleshooting**
- **Permission Errors:** Ensure you run commands with `sudo` where necessary.
- **Dependency Issues:** Verify that **TestDisk**, **PhotoRec**, and **Python dependencies** are installed correctly.
- **Git Issues:** Ensure you have network connectivity when using `--update`.

---

## **License and Contributions**
This project is open-source and contributions are welcome! If you encounter issues or have suggestions, feel free to open an issue on the [GitHub repository](https://github.com/Nakum-hub/frece).

---

## **Author**
Created by **Nakum-hub** for efficient and enhanced file recovery.

---

This updated README incorporates the features, installation instructions, commands, troubleshooting tips, and uninstallation details, making it a comprehensive guide for using and managing the FRECE tool.