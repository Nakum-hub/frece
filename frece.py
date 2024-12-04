#!/usr/bin/env python3

import os
import sys
import random
from colorama import Fore, Style, init
import shutil
try:
    import readline
except ImportError:
    import pyreadline as readline
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
        self.setup_tab_completion()

    def scan_directory(self, directory, extension=None):
            """
            Scans the directory and returns a list of files, optionally filtering by extension.
            Supports shorthand paths like 'Trash'.
            """
            # Ensure directory is a string before calling lower()
            if not isinstance(directory, str):
                print(Fore.RED + "Invalid directory path. It must be a string.")
                return []

            # Expand shorthand paths
            if directory.lower() == "trash":
                directory = os.path.expanduser("~/.local/share/Trash/files")  # For Linux
                if not os.path.exists(directory):  # Fallback for other OS
                    print(Fore.RED + "Trash directory is not accessible on this system.")
                    return []
            else:
                directory = os.path.expanduser(directory)
                directory = os.path.abspath(directory)

            try:
                if not os.path.exists(directory):
                    print(Fore.RED + f"Directory {directory} does not exist.")
                    return []

                if extension and not extension.startswith("."):
                    extension = f".{extension}"  # Automatically prepend the dot

                files = [file for file in Path(directory).rglob('*') if file.is_file()]
                if extension:
                    files = [file for file in files if file.suffix.lower() == extension.lower()]

                if files:
                    print(Fore.GREEN + f"Scanned {directory} and found {len(files)} files.")
                    if extension:
                        print(Fore.GREEN + f"Filtered by extension: {extension}")
                else:
                    print(Fore.YELLOW + f"No files found in {directory}.")

                return files
            except PermissionError:
                print(Fore.RED + "Permission denied while accessing the directory.")
                return []




    def list_files_with_types(self, directory):
        """
        Lists the types of files, file names, and directories in the given directory
        and counts their occurrences.
        """
        

        directory = os.path.abspath(os.path.expanduser(directory))

        if not os.path.exists(directory):
            print(Fore.RED + f"Directory {directory} does not exist.")
            return

        file_types = {}
        directory_count = 0
        files_info = []  # To store file names along with their extensions

        # Iterate through all items in the directory and its subdirectories
        for item in Path(directory).rglob('*'):
            if item.is_file():
                ext = item.suffix.lower() or "No Extension"
                file_types[ext] = file_types.get(ext, 0) + 1
                files_info.append((item.name, ext))  # Store file name and extension
            elif item.is_dir():
                directory_count += 1

        # Display directories
        if directory_count > 0:
            print(Fore.GREEN + f"\nDirectories Found: {directory_count}")
            for item in Path(directory).rglob('*'):
                if item.is_dir():
                    print(Fore.BLUE + f"Directory: {item}")

        # Display file types and their counts
        if file_types:
            print(Fore.CYAN + "\nFile Types Found:")
            for ext, count in file_types.items():
                print(f"{ext}: {count} file(s)")
        else:
            print(Fore.CYAN + "\nNo files found in the directory.")

        # Display file names and their extensions
        if files_info:
            print(Fore.YELLOW + "\nFiles Found:")
            for file_name, ext in files_info:
                print(f"File: {file_name}, Extension: {ext}")
        else:
            print(Fore.YELLOW + "\nNo files to display.")

        print(Fore.RESET)  # Reset color formatting after the output

    def setup_tab_completion(self):
        def tab_autocomplete(text, state):
            directory, partial = os.path.split(text)
            if not directory:
                directory = '.'
            try:
                entries = os.listdir(directory)
                options = [os.path.join(directory, f) for f in entries if f.startswith(partial)]
            except FileNotFoundError:
                options = []
            try:
                return options[state]
            except IndexError:
                return None

        try:
            readline.set_completer(tab_autocomplete)
            readline.parse_and_bind("tab: complete")
        except AttributeError:
            print("Tab completion is not supported on this platform.")


    def recover_files(self, source_dir, target_dir, extension=None):
        """
        Recovers files and directories from the source directory to the target directory.

        Args:
            source_dir (str): Path to the source directory.
            target_dir (str): Path to the target directory.
            extension (str, optional): File extension to filter files. Recovers all files if not specified.
        """
        try:
            print(Fore.GREEN + f"Starting recovery from {source_dir} to {target_dir}...")

            # Create the target directory if it doesn't exist
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
                print(Fore.GREEN + f"Created target directory: {target_dir}")

            # Check if source_dir exists
            if not os.path.exists(source_dir):
                print(Fore.RED + f"Source directory {source_dir} does not exist.")
                return

            # If extension is not specified, recover both files and directories
            if extension is None:
                # Traverse through all files and directories in source_dir
                for root, dirs, files in os.walk(source_dir):
                    # Recover directories
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        relative_dir_path = os.path.relpath(dir_path, source_dir)
                        target_dir_path = os.path.join(target_dir, relative_dir_path)

                        # Create the directory if it doesn't exist in the target
                        if not os.path.exists(target_dir_path):
                            os.makedirs(target_dir_path)
                            print(Fore.GREEN + f"Recovered directory: {target_dir_path}")

                    # Recover files
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        relative_file_path = os.path.relpath(file_path, source_dir)
                        target_file_path = os.path.join(target_dir, relative_file_path)

                        # Ensure the parent directory exists in the target before copying the file
                        os.makedirs(os.path.dirname(target_file_path), exist_ok=True)
                        shutil.copy(file_path, target_file_path)
                        print(Fore.GREEN + f"Recovered file: {target_file_path}")

            else:
                # If an extension is specified, recover only matching files
                for root, dirs, files in os.walk(source_dir):
                    for file_name in files:
                        if file_name.endswith(extension):
                            file_path = os.path.join(root, file_name)
                            relative_file_path = os.path.relpath(file_path, source_dir)
                            target_file_path = os.path.join(target_dir, relative_file_path)

                            # Ensure the parent directory exists in the target before copying the file
                            os.makedirs(os.path.dirname(target_file_path), exist_ok=True)
                            shutil.copy(file_path, target_file_path)
                            print(Fore.GREEN + f"Recovered file: {target_file_path}")

            print(Fore.GREEN + "Recovery completed successfully!")

        except Exception as e:
            print(Fore.RED + f"Error during recovery: {e}")

        def run_testdisk(self):
            """
            Automates TestDisk recovery process for partition or file recovery.
            """
            print("Running TestDisk...")
            try:
                # Use the directory on Desktop (or another location) where recovered files are stored
                recovery_directory = os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_Files")
                if not os.path.exists(recovery_directory):
                    os.makedirs(recovery_directory)
                    print(f"Created recovery directory: {recovery_directory}")
                
                # Run TestDisk using subprocess
                subprocess.run(["testdisk", "/d", recovery_directory], check=True)
                print(f"TestDisk completed. Results saved in: {recovery_directory}")
            
            except subprocess.CalledProcessError as e:
                print(f"TestDisk error: {e}")

    def run_photorec(self):
        """
        Automates PhotoRec recovery process to retrieve lost files by file signatures.
        """
        print("Running PhotoRec...")
        try:
            # Use the directory in Desktop (or another location) where recovered files are stored
            recovery_directory = os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_Files")
            
            # Create the recovery directory if it doesn't exist
            if not os.path.exists(recovery_directory):
                os.makedirs(recovery_directory)
                print(f"Created recovery directory: {recovery_directory}")
            
            # Run PhotoRec using subprocess
            subprocess.run(["photorec", "/d", recovery_directory], check=True)
            print(f"PhotoRec completed. Results saved in: {recovery_directory}")
        
        except subprocess.CalledProcessError as e:
            print(f"PhotoRec error: {e}")
        except Exception as e:
            print(f"An error occurred while running PhotoRec: {e}")

    def save_recovery(self, directory=None):
        """
        Saves recovered files to a specified directory or reuses an existing directory on the Desktop for recovered files.
        """
        try:
            # Default to a directory on the Desktop if none is provided
            if not directory:
                desktop = os.path.join(os.path.expanduser("~"), "Desktop")
                recovery_folder_name = "FRECE_Recovered"
                directory = os.path.join(desktop, recovery_folder_name)

            # Ensure the directory exists, or reuse it if already present
            if not os.path.exists(directory):
                os.makedirs(directory)
                print(Fore.GREEN + f"Directory '{directory}' created for recovered files.")
            else:
                print(Fore.YELLOW + f"Using existing directory: {directory}")

            print(Fore.GREEN + f"Saving recovered files to {directory}...")

            # Check if the recovery directory exists and has files to save
            if os.path.exists(RECOVERY_DIR) and os.listdir(RECOVERY_DIR):
                # Copy files from the RECOVERY_DIR to the specified directory
                for file in os.listdir(RECOVERY_DIR):
                    source_file = os.path.join(RECOVERY_DIR, file)
                    destination_file = os.path.join(directory, file)

                    # Ensure the destination directory exists before copying
                    os.makedirs(os.path.dirname(destination_file), exist_ok=True)
                    shutil.copy(source_file, destination_file)
                    print(Fore.GREEN + f"Recovered file saved: {destination_file}")

                print(Fore.GREEN + f"Files saved successfully to {directory}.")
            else:
                print(Fore.YELLOW + "No files found in the recovery directory to save.")

        except Exception as e:
            print(Fore.RED + f"Error saving files: {e}")

    def show_help(self):
        """
        Displays help information for all available commands, including the new 'list' command.
        """
        print(Fore.CYAN + """Available Commands:
        recover <source_dir> <target_dir> - Recover files and directories from source to target directory.
        scan <directory> [extension]      - Scan a directory for files; filter by extension if specified.
        list <directory>                  - List file types and their counts in the specified directory.
        list_files_with_types <directory> - List detailed file types, file names, and directories in the specified directory.
        man <command>                     - Display manual for a specific command.
        testdisk                          - Run TestDisk for data recovery, recovered files will be saved on the Desktop.
        photorec                          - Run PhotoRec for data recovery, recovered files will be saved on the Desktop.
        save <directory>                  - Save recovered files to a specified directory.
        --version                         - Show the tool version.
        --help                            - Display this help message.
        exit                              - Exit the interactive mode.

        Tab Autocomplete Feature:
        - You can use the Tab key to autocomplete file paths, directories, and commands, similar to Kali Linux.
        - It works for file paths, directories, and command names in the interactive mode, enhancing user navigation and efficiency.

        Example Usages:
        - recover /path/to/source /path/to/target
        - scan /path/to/directory .txt
        - list /path/to/directory
        - list_files_with_types /path/to/directory
        - testdisk
        - photorec
        - save /path/to/save/directory""")

    def show_command_man(self, command):
        """
        Displays a detailed manual for a specific command, including the new 'list' command and 'man frece' as a README.
        """
        manuals = {
            'recover': "Recover files from source to target directory.\nUsage: recover <source_dir> <target_dir>",
            'scan': "Scan a directory for files, optionally filtering by extension.\nUsage: scan <directory> [extension]",
            'list': ("List all file types in the specified directory and their counts.\n"
                    "Usage: list <directory>\n"
                    "Example: list ~/Documents"),
            'list_files_with_types': ("List detailed file types, file names, and directories in the specified directory.\n"
                                    "Usage: list_files_with_types <directory>\n"
                                    "Example: list_files_with_types ~/Documents"),
            'testdisk': "Run TestDisk to recover partitions and files.\nUsage: testdisk",
            'photorec': "Run PhotoRec to recover lost files by file signatures.\nUsage: photorec",
            'save': "Save recovered files to the specified directory.\nUsage: save <directory>",
            '--version': "Display the version of this tool.\nUsage: --version",
            '--help': "Display help for commands.\nUsage: --help",
            'frece': ("FRECE (File Recovery Console Enhanced) is a powerful tool designed for recovering files, "
                    "scanning directories for lost data, and providing data recovery options through utilities like TestDisk and PhotoRec.\n"
                    "\nFeatures:\n"
                    "  - Recover files from source to target directory\n"
                    "  - Scan directories for files, optionally filtering by extension\n"
                    "  - List file types and counts in directories\n"
                    "  - Recover lost partitions and files with TestDisk\n"
                    "  - Recover files using file signatures with PhotoRec\n"
                    "  - Save recovered files to a user-specified directory\n"
                    "  - Tab autocomplete for file paths, directories, and commands\n"
                    "  - Display tool version and help information\n"
                    "\nUsage examples:\n"
                    "  - recover /path/to/source /path/to/target\n"
                    "  - scan /path/to/directory .txt\n"
                    "  - list /path/to/directory\n"
                    "  - testdisk\n"
                    "  - photorec\n"
                    "  - save /path/to/save/directory\n"
                    "  - --version\n"
                    "  - --help"),
        }
        
        print(Fore.CYAN + manuals.get(command, "No manual entry for this command."))




    def interactive_mode(self):
        """
        Interactive mode for the FRECE tool with looping until 'exit' is entered.
        """
        print(Fore.GREEN + f"Welcome to FRECE interactive mode!")
        while True:
            try:
                command = input(Fore.YELLOW + "frece > ").strip()

                if command.startswith("recover"):
                    command_parts = command.split()
                    if len(command_parts) == 3:  # source, target
                        _, source, target = command_parts
                        
                        # Validate source and target directories
                        if not os.path.exists(source):
                            print(Fore.RED + f"Source directory {source} does not exist.")
                        elif not os.path.exists(target):
                            print(Fore.RED + f"Target directory {target} does not exist. Creating it now.")
                            os.makedirs(target, exist_ok=True)
                            print(Fore.GREEN + f"Created target directory: {target}")
                        
                        else:
                            print(Fore.GREEN + f"Recovering all files and directories from {source} to {target}...")
                            self.recover_files(source, target)  # Recover both files and directories

                    elif len(command_parts) == 4:  # source, extension, target
                        _, source, extension, target = command_parts
                        
                        # Validate source and target directories
                        if not os.path.exists(source):
                            print(Fore.RED + f"Source directory {source} does not exist.")
                        elif not os.path.exists(target):
                            print(Fore.RED + f"Target directory {target} does not exist. Creating it now.")
                            os.makedirs(target, exist_ok=True)
                            print(Fore.GREEN + f"Created target directory: {target}")
                        
                        else:
                            print(Fore.GREEN + f"Recovering files with extension {extension} from {source} to {target}...")
                            self.recover_files(source, target, extension)  # Recover files with a specified extension

                    else:
                        print(Fore.RED + "Invalid number of arguments. Usage: recover <source_dir> [extension] <target_dir>")

                elif command.startswith("scan"):
                    parts = command.split(maxsplit=2)
                    if len(parts) >= 2:
                        directory = parts[1]
                        ext = parts[2] if len(parts) == 3 else None
                        files = self.scan_directory(directory, ext)
                        print(Fore.GREEN + f"Found {len(files)} files in {directory}.")
                        if ext:
                            print(Fore.GREEN + f"Files filtered by extension: {ext}")
                    else:
                        print(Fore.RED + "Usage: scan <directory> [extension]")

                elif command.startswith("list"):
                    parts = command.split(maxsplit=1)
                    if len(parts) == 2:
                        directory = parts[1]
                        print(Fore.GREEN + f"Listing file types, file names, and directories in: {directory}...")
                        self.list_files_with_types(directory)
                    else:
                        print(Fore.RED + "Usage: list <directory>")


                elif command.startswith("man"):
                    parts = command.split(maxsplit=1)
                    if len(parts) == 2:
                        cmd = parts[1]
                        if cmd == "frece":
                            print(Fore.CYAN + "Displaying full tool overview (README-style)...")
                            self.show_command_man('frece')  # Show the detailed 'frece' manual
                        else:
                            self.show_command_man(cmd)  # Show manual for specific command
                    else:
                        print(Fore.RED + "Usage: man <command>")


                elif command == "testdisk":
                        try:
                            # Ensure the recovered files from testdisk go to the Desktop folder
                            recovery_directory = os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_Files")
                            if not os.path.exists(recovery_directory):
                                os.makedirs(recovery_directory)
                                print(Fore.GREEN + f"Created recovery directory: {recovery_directory}")
                            self.run_testdisk(recovery_directory)  # Pass the recovery directory to the method
                        except AttributeError as e:
                            print(Fore.RED + f"An error occurred: {e}. Ensure 'run_testdisk' is implemented and accessible.")
                        except Exception as e:
                            print(Fore.RED + f"An unexpected error occurred while running TestDisk: {e}")

                elif command == "photorec":
                        try:
                            # Ensure the recovered files from photorec go to the Desktop folder
                            recovery_directory = os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_Files")
                            if not os.path.exists(recovery_directory):
                                os.makedirs(recovery_directory)
                                print(Fore.GREEN + f"Created recovery directory: {recovery_directory}")
                            self.run_photorec(recovery_directory)  # Pass the recovery directory to the method
                        except AttributeError as e:
                            print(Fore.RED + f"An error occurred: {e}. Ensure 'run_photorec' is implemented and accessible.")
                        except Exception as e:
                            print(Fore.RED + f"An unexpected error occurred while running PhotoRec: {e}")


                elif command.startswith("save"):
                    parts = command.split(maxsplit=1)
                    if len(parts) == 2:
                        directory = parts[1]
                        self.save_recovery(directory)  # Save the recovered files to the specified directory
                    else:
                        print(Fore.RED + "Usage: save <directory>")

                elif command == "--version":
                    print(self.version)

                elif command == "--help":
                    self.show_help()  # Display help for all commands

                elif command == "exit":
                    print(Fore.GREEN + "Exiting interactive mode.")
                    break

                else:
                    print(Fore.RED + "Invalid command. Type '--help' for a list of commands.")

            except Exception as e:
                print(Fore.RED + f"An error occurred: {e}. Please try again or type '--help' for guidance.")



    def start(self):
            """
            Entry point for the tool to process CLI arguments or launch interactive mode.
            """
            try:
                if len(sys.argv) > 1:
                    args = sys.argv[1:]
                    command = args[0]

                    if command == '--version':
                        print(self.version)

                    elif command == '--help':
                        self.show_help()  # Display help for all commands

                    elif command == 'recover':
                        if len(args) < 3:
                            print(Fore.RED + "Usage: recover <source_dir> <target_dir> [extension]")
                        else:
                            source = args[1]
                            target = args[2]
                            extension = args[3] if len(args) > 3 else None

                            # Validate source directory existence
                            if not os.path.exists(source):
                                print(Fore.RED + f"Source directory '{source}' does not exist.")
                            elif not os.path.exists(target):
                                # If target directory doesn't exist, create it
                                print(Fore.RED + f"Target directory '{target}' does not exist. Creating target directory.")
                                os.makedirs(target, exist_ok=True)  # Create the target directory if it doesn't exist
                                print(Fore.GREEN + f"Created target directory: {target}")
                            else:
                                # Inform the user of the recovery operation
                                if extension:
                                    print(Fore.GREEN + f"Recovering files with extension '{extension}' from {source} to {target}...")
                                else:
                                    print(Fore.GREEN + f"Recovering all files and directories from {source} to {target}...")

                                # Call the recovery method
                                self.recover_files(source, target, extension)

                                # Check if any files were recovered (for feedback)
                                if extension:
                                    # If extension is specified, check for matching files
                                    files_recovered = [file for file in os.listdir(source) if file.endswith(extension)]
                                    if not files_recovered:
                                        print(Fore.YELLOW + f"No files with extension '{extension}' found in {source}.")
                                else:
                                    # If no extension is specified, simply inform the user about the recovery
                                    print(Fore.GREEN + f"Recovery from {source} to {target} completed.")

                    elif command == 'scan':
                        if len(args) < 2:
                            print(Fore.RED + "Usage: scan <directory> [extension]")
                        else:
                            directory = args[1]
                            extension = args[2] if len(args) > 2 else None

                            if not os.path.exists(directory):
                                print(Fore.RED + f"Directory '{directory}' does not exist.")
                            else:
                                files = self.scan_directory(directory, extension)
                                print(Fore.GREEN + f"Found {len(files)} files in '{directory}'.")
                                if extension:
                                    print(Fore.GREEN + f"Filtered by extension: {extension}")


                    elif command == 'list':
                        if len(args) < 2:
                            print(Fore.RED + "Usage: list <directory>")
                        else:
                            directory = args[1]
                            if not os.path.exists(directory):
                                print(Fore.RED + f"Directory '{directory}' does not exist.")
                            else:
                                print(Fore.GREEN + f"Listing file types, file names, and directories in: {directory}...")
                                self.list_files_with_types(directory)
                    

                    elif command == 'man':
                        if len(args) < 2:
                            print(Fore.RED + "Usage: man <command>")
                        else:
                            # Check if it's 'frece' to show full tool documentation (README-style)
                            if args[1] == "frece":
                                print(Fore.CYAN + "Displaying full tool overview (README-style)...")
                                self.show_command_man('frece')  # Show the detailed 'frece' manual
                            else:
                                self.show_command_man(args[1])  # Show manual for specific command

                    elif command == 'testdisk':
                        try:
                            # Ensure the recovered files go to the Desktop's Recovered_Files directory
                            recovery_directory = os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_Files")
                            if not os.path.exists(recovery_directory):
                                os.makedirs(recovery_directory)
                                print(Fore.GREEN + f"Created recovery directory: {recovery_directory}")
                            self.run_testdisk(recovery_directory)  # Pass the recovery directory to the method
                        except AttributeError as e:
                            print(Fore.RED + f"An error occurred: {e}. Ensure 'run_testdisk' is implemented and accessible.")
                        except Exception as e:
                            print(Fore.RED + f"An unexpected error occurred while running TestDisk: {e}")

                    elif command == 'photorec':
                        try:
                            # Ensure the recovered files go to the Desktop's Recovered_Files directory
                            recovery_directory = os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_Files")
                            if not os.path.exists(recovery_directory):
                                os.makedirs(recovery_directory)
                                print(Fore.GREEN + f"Created recovery directory: {recovery_directory}")
                            self.run_photorec(recovery_directory)  # Pass the recovery directory to the method
                        except AttributeError as e:
                            print(Fore.RED + f"An error occurred: {e}. Ensure 'run_photorec' is implemented and accessible.")
                        except Exception as e:
                            print(Fore.RED + f"An unexpected error occurred while running PhotoRec: {e}")


                    elif command == 'save':
                        if len(args) < 2:
                            print(Fore.RED + "Usage: save <directory>")
                        else:
                            directory = args[1]
                            
                            # Check if the directory exists
                            if not os.path.exists(directory):
                                print(Fore.RED + f"Directory '{directory}' does not exist. Creating directory.")
                                os.makedirs(directory, exist_ok=True)  # Create the directory if it doesn't exist
                                print(Fore.GREEN + f"Created directory: {directory}")
                            else:
                                print(Fore.GREEN + f"Using existing directory: {directory}")
                            
                            # Attempt to save recovered files to the directory
                            try:
                                self.save_recovery(directory)
                                print(Fore.GREEN + f"Files saved successfully to {directory}.")
                            except Exception as e:
                                print(Fore.RED + f"Error saving files: {e}")

                    else:
                        print(Fore.RED + "Invalid command. Type '--help' for usage.")

                    # Handle case when no arguments are provided
                else:
                        # Display dynamic banner and enter interactive mode if no arguments are provided
                        display_dynamic_banner()
                        self.interactive_mode()

                    # Handle any general exceptions
            except Exception as e:
                print(Fore.RED + f"An error occurred: {e}")



# ================== Execution ==================

if __name__ == "__main__":
    tool = FRECE()  # Instantiate the FRECE class
    tool.start()    # Call the start method
