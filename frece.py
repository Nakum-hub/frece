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

# Initialize colorama for terminal colors
init(autoreset=True)

# Constants for file recovery directory
RECOVERY_DIR = os.path.join(Path.home(), "Desktop", "Recovered_files")

# ================== Utility Functions ==================

def display_dynamic_banner():
    """
    Displays a dynamic banner for the tool to make the interface more engaging.
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
    print(random.choice(banners))  # Display one of the predefined banners randomly

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
    """
    FRECE (File Recovery Enhanced Command-line Environment) is the core class
    containing the primary functionality for file scanning, recovery, and tool integration.
    """

    def __init__(self):
        self.version = "FRECE v1.0"

    def scan_directory(self, directory, extension=None):
        """
        Scans a directory for files and optionally filters by file extension.
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

    def run_testdisk(self):
        """
        Automates TestDisk recovery process for partition or file recovery.
        """
        print("Running TestDisk...")
        try:
            subprocess.run(["testdisk"], check=True)
            print(f"TestDisk completed. Results saved in: {RECOVERY_DIR}")
        except subprocess.CalledProcessError as e:
            print(f"TestDisk error: {e}")

    def run_photorec(self):
        """
        Automates PhotoRec recovery process to retrieve lost files by file signatures.
        """
        print("Running PhotoRec...")
        try:
            subprocess.run(["photorec", "/d", RECOVERY_DIR], check=True)
            print(f"PhotoRec completed. Results saved in: {RECOVERY_DIR}")
        except subprocess.CalledProcessError as e:
            print(f"PhotoRec error: {e}")

    def save_recovery(self, directory):
        """
        Saves recovered files to a specified directory for user-defined organization.
        """
        print(f"Saving recovered files to {directory}")
        if not os.path.exists(directory):
            os.makedirs(directory)
        try:
            for file in os.listdir(RECOVERY_DIR):
                shutil.copy(os.path.join(RECOVERY_DIR, file), directory)
            print(Fore.GREEN + "Files saved successfully.")
        except Exception as e:
            print(Fore.RED + f"Error saving files: {e}")

    def show_help(self):
        """
        Displays help information for all available commands.
        """
        print(Fore.CYAN + """Available Commands:
    recover <source_dir> <target_dir> - Recover files from source to target directory.
    scan <directory> [extension]      - Scan directory for files; filter by extension if specified.
    man <command>                    - Display manual for a specific command.
    testdisk                         - Run TestDisk for recovery.
    photorec                         - Run PhotoRec for recovery.
    save <directory>                 - Save recovered files to a specified directory.
    --version                        - Show the tool version.
    --help                           - Display this help message.
    exit                             - Exit the interactive mode.""")

    def show_command_man(self, command):
        """
        Displays a detailed manual for a specific command.
        """
        manuals = {
            'recover': "Recover files from source to target directory.",
            'scan': "Scan a directory for files, optionally filtering by extension.",
            'testdisk': "Run TestDisk to recover partitions and files.",
            'photorec': "Run PhotoRec to recover lost files by file signatures.",
            'save': "Save recovered files to the specified directory.",
            '--version': "Display the version of this tool.",
            '--help': "Display help for commands."
        }
        print(Fore.CYAN + manuals.get(command, "No manual entry for this command."))

    def interactive_mode(self):
        """
        Provides an interactive command-line interface for executing tool commands.
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
            elif command == "testdisk":
                self.run_testdisk()
            elif command == "photorec":
                self.run_photorec()
            elif command.startswith("save"):
                _, directory = command.split()
                self.save_recovery(directory)
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
        Entry point for the tool to process CLI arguments or launch interactive mode.
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
            elif args[0] == 'testdisk':
                self.run_testdisk()
            elif args[0] == 'photorec':
                self.run_photorec()
            elif args[0] == 'save':
                self.save_recovery(args[1])
            else:
                print(Fore.RED + "Invalid command. Type '--help' for usage.")
        else:
            display_dynamic_banner()
            self.interactive_mode()

# ================== Execution ==================

if __name__ == "__main__":
    tool = FRECE()
    tool.start()
