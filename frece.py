#!/usr/bin/env python3

import os
import sys
import random
from colorama import Fore, Style, init
import shutil
from pathlib import Path
import subprocess

# Conditional import for Windows systems
if sys.platform == "win32":
    try:
        import pyreadline as readline  # For command history on Windows
    except ImportError:
        print("pyreadline not found, running without command history.")
else:
    import readline  # For command history on Unix-based systems

# Initialize colorama
init(autoreset=True)

# Constants
RECOVERY_DIR = os.path.join(Path.home(), "Desktop", "Recovered_files")

# ================== Utility Functions ==================

def display_dynamic_banner():
    """
    Displays a dynamic banner for the tool.
    """
    banners = [
        f"""{Fore.RED}
   **** **  **                                                                               
  /**/ //  /**                                                                        **   **
 ****** ** /**  *****        ******  *****   *****   ******  **    **  *****  ****** //** ** 
///**/ /** /** **///**      //**//* **///** **///** **////**/**   /** **///**//**//*  //***  
  /**  /** /**/*******       /** / /*******/**  // /**   /**//** /** /******* /** /    /**   
  /**  /** /**/**////        /**   /**//// /**   **/**   /** //****  /**////  /**      **    
  /**  /** ***//******      /***   //******//***** //******   //**   //******/***     **     
  //   // ///  //////       ///     //////  /////   //////     //     ////// ///     //      
{Fore.CYAN}File Recovery Tool
{Style.RESET_ALL}"""
    ]
    print(random.choice(banners))  # Randomly select a banner

def install_dependencies():
    """
    Automatically installs required tools like TestDisk and PhotoRec.
    """
    tools = ["testdisk", "photorec"]
    missing_tools = [tool for tool in tools if not shutil.which(tool)]
    
    if missing_tools:
        print("Installing missing dependencies:", ", ".join(missing_tools))
        try:
            subprocess.run(["sudo", "apt", "update"], check=True)
            subprocess.run(["sudo", "apt", "install", "-y"] + missing_tools, check=True)
            print("Dependencies installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install dependencies: {e}")
            sys.exit(1)
    else:
        print("All required dependencies are already installed.")

# ================== Core Recovery Class ==================

class FRECE:
    def __init__(self):
        self.version = "FRECE v1.0"

    def scan_directory(self, directory, extension=None):
        """
        Scans the directory and returns a list of files, optionally filtering by extension.
        """
        try:
            if not os.path.exists(directory):
                print(Fore.RED + f"Directory {directory} does not exist.")
                return []
            files = [file for file in Path(directory).rglob('*') if file.is_file()]
            if extension:
                files = [file for file in files if file.suffix.lower() == extension.lower()]
            return files
        except PermissionError:
            print(Fore.RED + "Permission denied.")
            return []

    def recover_files(self, source, target):
        """
        Recovers files from the source directory to the target directory.
        """
        if not os.path.exists(target):
            os.makedirs(target)
        try:
            files = self.scan_directory(source)
            if not files:
                print(Fore.RED + "No files found to recover.")
                return
            for file in files:
                shutil.copy(file, target)
                print(Fore.GREEN + f"Recovered: {file}")
        except Exception as e:
            print(Fore.RED + f"Error during file recovery: {e}")

    def show_help(self):
        """
        Displays help for available commands.
        """
        print(Fore.CYAN + """Available Commands:
    recover <source_dir> <target_dir> - Recover files from source to target.
    scan <directory> [extension]      - Scan directory for files, optionally filter by extension.
    man <command>                    - Show manual for a command.
    --version                        - Show the tool version.
    --help                           - Show this help.""")

    def show_command_man(self, command):
        """
        Displays the manual for a specific command.
        """
        manuals = {
            'recover': """
Recover Command:
Usage: recover <source_dir> <target_dir>
Description: This command recovers files from the source directory to the target directory.
            """,
            'scan': """
Scan Command:
Usage: scan <directory> [extension]
Description: This command scans the specified directory and returns a list of files.
             Optionally, filter files by their extension.
            """
        }
        print(Fore.CYAN + manuals.get(command, "No manual found for this command."))

    def interactive_mode(self):
        """
        Interactive mode to handle user commands.
        """
        print(Fore.GREEN + f"Welcome to FRECE interactive mode!")
        while True:
            command = input(Fore.YELLOW + "Enter command: ").strip()
            if command.startswith("recover"):
                _, source, target = command.split()
                self.recover_files(source, target)
            elif command.startswith("scan"):
                _, directory, *ext = command.split()
                ext = ext[0] if ext else None
                files = self.scan_directory(directory, ext)
                print(Fore.GREEN + f"Found {len(files)} files.")
            elif command.startswith("man"):
                _, cmd = command.split()
                self.show_command_man(cmd)
            elif command == "--version":
                print(self.version)
            elif command == "--help":
                self.show_help()
            elif command == "exit":
                print(Fore.GREEN + "Exiting interactive mode.")
                break
            else:
                print(Fore.RED + "Invalid command. Type '--help' for a list of commands.")

    def start(self):
        """
        Entry point for the tool.
        """
        if len(sys.argv) > 1:
            args = sys.argv[1:]
            if args[0] == '--version':
                print(self.version)
            elif args[0] == '--help':
                self.show_help()
            elif args[0] == 'recover':
                self.recover_files(args[1], args[2])
            elif args[0] == 'scan':
                extension = args[2] if len(args) > 2 else None
                files = self.scan_directory(args[1], extension)
                print(f"Found {len(files)} files.")
            elif args[0] == 'man':
                self.show_command_man(args[1])
            else:
                print(Fore.RED + "Invalid command. Type '--help' for usage.")
        else:
            display_dynamic_banner()
            self.interactive_mode()

# ================== Recovery Tools ==================

def scan_all_files(directory):
    """
    Recursively scans directories for all types of files.
    """
    try:
        print(f"Scanning directory: {directory}")
        files = [file for file in Path(directory).rglob('*') if file.is_file()]
        print(f"Found {len(files)} files.")
        return files
    except Exception as e:
        print(f"Error scanning directory: {e}")
        return []

def recover_all_files(files):
    """
    Copies detected files to the RECOVERY_DIR.
    """
    if not os.path.exists(RECOVERY_DIR):
        os.makedirs(RECOVERY_DIR)
        print(f"Created recovery directory: {RECOVERY_DIR}")
    
    for file in files:
        try:
            recovery_path = os.path.join(RECOVERY_DIR, os.path.basename(file))
            shutil.copy(file, recovery_path)
            print(f"Recovered: {file} -> {recovery_path}")
        except Exception as e:
            print(f"Error recovering {file}: {e}")
    print(f"Recovered files are stored in: {RECOVERY_DIR}")

def run_testdisk_automated():
    """
    Automates TestDisk recovery process.
    """
    print("Running TestDisk for partition and file recovery...")
    try:
        subprocess.run(["testdisk"], check=True)
        print(f"TestDisk completed. Recovered files are saved in: {RECOVERY_DIR}")
    except subprocess.CalledProcessError as e:
        print("Error occurred while running TestDisk:", e)

def run_photorec_automated():
    """
    Automates PhotoRec recovery process and directs output to RECOVERY_DIR.
    """
    print("Running PhotoRec for file recovery...")
    try:
        subprocess.run(["photorec", "/d", RECOVERY_DIR], check=True)
        print(f"PhotoRec completed. Recovered files are saved in: {RECOVERY_DIR}")
    except subprocess.CalledProcessError as e:
        print("Error occurred while running PhotoRec:", e)

def recovery_with_tools():
    """
    Unified function to handle recovery with TestDisk and PhotoRec.
    """
    print("Choose a recovery method:")
    print("1. TestDisk - Partition and file system recovery")
    print("2. PhotoRec - File recovery")
    print("3. Back to Main Menu")
    choice = input("Enter your choice: ")
    if choice == "1":
        run_testdisk_automated()
    elif choice == "2":
        run_photorec_automated()
    elif choice == "3":
        return
    else:
        print("Invalid choice. Please try again.")

# ================== Main CLI ==================

def main():
    """
    Main function to handle command-line arguments for directory scanning,
    file recovery, and advanced recovery tools.
    """
    install_dependencies()

    print("Welcome to FRECE Recovery Tool!")
    print("Options:")
    print("1. Scan and recover files from a directory")
    print("2. Advanced recovery using TestDisk or PhotoRec")
    print("3. Exit")
    choice = input("Enter your choice: ")
    
    if choice == "1":
        directory = input("Enter the directory to scan: ")
        if not os.path.exists(directory):
            print(f"Directory {directory} does not exist.")
            sys.exit(1)
        
        print(f"Starting scan and recovery...")
        files = scan_all_files(directory)
        if not files:
            print("No files found to recover.")
            return
        
        recover_all_files(files)
    elif choice == "2":
        recovery_with_tools()
    elif choice == "3":
        print("Exiting the tool.")
        sys.exit(0)
    else:
        print("Invalid option. Please try again.")

# ================== Execution ==================

if __name__ == "__main__":
    tool = FRECE()
    tool.start()
