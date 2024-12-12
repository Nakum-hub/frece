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
import platform


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

    INSTALL_DIR = "/usr/local/bin"  # Default installation directory
    TOOL_NAME = "frece"  # Main tool name for installation
    SCRIPT_NAME = "frece.py"  # Name of the Python script
    VENV_DIR = os.path.expanduser("~/frece_venv")  # Virtual environment location
    FRECE_DIR = "/home/kali/frece"  # Installation directory for the tool
    REPO_DIR = os.path.join(FRECE_DIR, "REPO_DIR/subfolder")  # Directory where the repository is cloned

    def create_directories(self):
        """Ensure necessary directories exist."""
        if not os.path.exists(self.REPO_DIR):
            os.makedirs(self.REPO_DIR, exist_ok=True)
            print(Fore.GREEN + f"Created repository directory: {self.REPO_DIR}")

    def update_tool(self):
        """Update the tool from the GitHub repository."""
        try:
            self.create_directories()  # Ensure REPO_DIR exists

            # Check if the repository exists and update it
            if os.path.exists(self.REPO_DIR):
                print(Fore.GREEN + "Updating the tool...")
                os.chdir(self.REPO_DIR)
                subprocess.run(["git", "pull", "origin", "main"], check=True)
                print(Fore.GREEN + "Tool updated successfully!")
            else:
                print(Fore.RED + f"Repository not found at {self.REPO_DIR}. Please reinstall the tool.")
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"Git update failed: {e}")
        except Exception as e:
            print(Fore.RED + f"An error occurred during the update process: {e}")


    def __init__(self):
        self.version = "FRECE v1.0"
        self.setup_tab_completion()
        # Set the path where the repo will be located on the Desktop
        self.REPO_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_files")

    def scan_directory(self, directory, extension=None):
        # Expand to user home directory
        home_dir = os.path.expanduser("~")

        # Map common shorthand directories, if specified, to their paths
        shorthand_paths = {
            "desktop": os.path.join(home_dir, "Desktop"),
            "documents": os.path.join(home_dir, "Documents"),
            "downloads": os.path.join(home_dir, "Downloads"),
            "pictures": os.path.join(home_dir, "Pictures"),
            "trash": os.path.join(home_dir, ".local/share/Trash/files"),
        }

        # Use shorthand if provided
        dir_lower = directory.lower()
        if dir_lower in shorthand_paths:
            full_path = shorthand_paths[dir_lower]
        else:
            full_path = os.path.abspath(directory)  # Resolve to an absolute path

        # Check if the directory exists and is accessible
        if not os.path.exists(full_path):
            # Additional handling for the root user
            if os.geteuid() == 0:  # Check if running as root
                print(Fore.YELLOW + f"Running as root. Attempting to scan '{full_path}' anyway.")
                # If the directory does not exist, show a message but allow the scan
                pass  # Continue to attempt the scan for root access
            
            print(Fore.RED + f"Directory '{full_path}' does not exist.")
            return

        # Attempt to scan the directory
        if os.path.isdir(full_path):
            try:
                files = os.listdir(full_path)

                # Filter by extension if specified
                if extension:
                    files = [f for f in files if f.endswith(extension)]

                found_files = len(files)
                print(f"Scanned '{full_path}' and found {found_files} files.")

                for file in files:
                    print(file)  # List the files
            except PermissionError:
                print(Fore.RED + f"'{full_path}' is not accessible on this system.")
                print(f"Found 0 files in '{directory}'.")
            except Exception as e:
                print(Fore.RED + f"An error occurred while scanning: {e}")
        else:
            print(Fore.RED + f"'{full_path}' is not a valid directory.")
            print(f"Found 0 files in '{directory}'.")


    def run_scan_command(self, args):
        if len(args) < 1:
            print(Fore.RED + "Usage: scan <directory> [extension]")
            return

        directory = args[0]  # The first argument is the directory
        extension = args[1] if len(args) > 1 else None  # Optional extension if provided

        # Call the scan_directory method
        self.scan_directory(directory, extension)

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
            options = []
            directory, partial = os.path.split(text)

            # Default to current directory if none specified
            if not directory:
                directory = '.'

            # Attempt to list all directories in the specified path
            try:
                # Gather all directories/files present in the current directory
                entries = os.listdir(directory)
                options = [os.path.join(directory, f) for f in entries if f.startswith(partial)]
            except FileNotFoundError:
                options = []  # If the directory doesn't exist, return an empty list
            except PermissionError:
                options = []  # Handle case where directory access is denied

            # Provide the options based on the current state
            if state < len(options):
                return options[state]
            else:
                return None

        # Set the tab completer
        try:
            readline.set_completer(tab_autocomplete)
            readline.parse_and_bind("tab: complete")
        except AttributeError:
            print("Tab completion is not supported on this platform.")


    def recover_files(self, source_dir, target_dir=None, extension=None):
        """
        Recovers files and directories from the source directory to the target directory.

        Args:
            source_dir (str): Path to the source directory.
            target_dir (str, optional): Path to the target directory.
            extension (str, optional): File extension to filter files. Recovers all files if not specified.
        """
        try:
            # Expand user directory if necessary
            source_dir = os.path.expanduser(source_dir)
            if target_dir:
                target_dir = os.path.expanduser(target_dir)
            else:
                # Default to the directory where hunter and slayer will store recovered files
                target_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_files")

            # Create the target directory if it doesn't exist
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
                print(Fore.GREEN + f"Created target directory: {target_dir}")

            # Check if source_dir exists
            if not os.path.exists(source_dir):
                print(Fore.RED + f"Source directory {source_dir} does not exist.")
                return

            # Analyze the source directory and check for file/folder existence
            if extension != 'null':
                if extension:  # If extension is specified, process it
                    # Recover files with the specified extension
                    for root, dirs, files in os.walk(source_dir):
                        for file_name in files:
                            if file_name.endswith(extension):
                                file_path = os.path.join(root, file_name)
                                relative_file_path = os.path.relpath(file_path, source_dir)
                                target_file_path = os.path.join(target_dir, relative_file_path)
                                os.makedirs(os.path.dirname(target_file_path), exist_ok=True)
                                shutil.copy(file_path, target_file_path)
                                print(Fore.GREEN + f"Recovered file: {target_file_path}")

                else:  # If extension is null, recover all files
                    # Traverse through all files and directories in source_dir
                    for root, dirs, files in os.walk(source_dir):
                        # Recover directories
                        for dir_name in dirs:
                            dir_path = os.path.join(root, dir_name)
                            relative_dir_path = os.path.relpath(dir_path, source_dir)
                            target_dir_path = os.path.join(target_dir, relative_dir_path)
                            os.makedirs(target_dir_path, exist_ok=True)
                            print(Fore.GREEN + f"Recovered directory: {target_dir_path}")

                        # Recover files
                        for file_name in files:
                            file_path = os.path.join(root, file_name)
                            relative_file_path = os.path.relpath(file_path, source_dir)
                            target_file_path = os.path.join(target_dir, relative_file_path)
                            os.makedirs(os.path.dirname(target_file_path), exist_ok=True)
                            shutil.copy(file_path, target_file_path)
                            print(Fore.GREEN + f"Recovered file: {target_file_path}")

            else:  # If no extension, recover files and directories matching the name
                # Recover files and directories with the name given in the filename
                for root, dirs, files in os.walk(source_dir):
                    for file_name in files + dirs:
                        # Check if the file or directory matches the given name (without extension)
                        if file_name == extension:
                            full_path = os.path.join(root, file_name)
                            relative_path = os.path.relpath(full_path, source_dir)
                            target_path = os.path.join(target_dir, relative_path)

                            # Recover directories
                            if os.path.isdir(full_path):
                                os.makedirs(target_path, exist_ok=True)
                                print(Fore.GREEN + f"Recovered directory: {target_path}")
                            else:
                                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                                shutil.copy(full_path, target_path)
                                print(Fore.GREEN + f"Recovered file: {target_path}")

            print(Fore.GREEN + "Recovery completed successfully!")

        except Exception as e:
            print(Fore.RED + f"Error during recovery: {e}")
        

    def get_installed_tool_path(self, tool_name):
            """
            Helper method to locate the tool's executable path using the 'which' command for Linux
            or 'where' command for Windows.
            Returns the path if found, else None.
            """
            try:
                if platform.system() == 'Linux':  # For Linux
                    result = subprocess.run(['which', tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                elif platform.system() == 'Windows':  # For Windows
                    result = subprocess.run(['where', tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                else:
                    raise Exception("Unsupported OS")

                tool_path = result.stdout.decode('utf-8').strip()
                return tool_path if tool_path else None
            except subprocess.CalledProcessError:
                return None

    def run_hunter(self):  # Enhanced for identifying and highlighting deleted files
        print(f"Running {self.hunter_tool}...")

        try:
            # Set default recovery directory on the desktop
            desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
            self.recovery_directory = os.path.join(desktop_dir, "Recovered_Files")

            # Ensure the default recovery directory exists
            if not os.path.exists(self.recovery_directory):
                os.makedirs(self.recovery_directory)
                print(Fore.GREEN + f"Created recovery directory: {self.recovery_directory}")

            # Display guidance for Hunter usage
            print(Fore.CYAN + "Starting Hunter in recovery mode...")
            print(Fore.YELLOW + "Follow these steps in Hunter to recover permanently deleted files:")
            print("1. Select the appropriate disk where the file was stored.")
            print("2. Choose your partition table type (or accept the default).")
            print("3. Select 'Advanced' for file system utilities.")
            print("4. Navigate to the directory or perform a deeper search.")
            print("5. Use 'Undelete' to recover deleted files.")
            print("6. If the file isn't listed, try 'Analyse' and perform a deeper search to scan unallocated space for the file.")

            # Run the Hunter tool (formerly TestDisk)
            log_file = os.path.join(self.recovery_directory, "hunter.log")
            subprocess.run(["sudo", "/usr/bin/testdisk", "/log"], cwd=self.recovery_directory, check=True)

            # Rename the log file to hunter.log if it is created with the original name
            testdisk_log_file = os.path.join(self.recovery_directory, "testdisk.log")
            if os.path.exists(testdisk_log_file):
                os.rename(testdisk_log_file, log_file)
                print(Fore.GREEN + "Log file renamed to hunter.log.")

            # Replace all references to "testdisk" in the log file content with "hunter"
            if os.path.exists(log_file):
                print(Fore.GREEN + "Processing Hunter log to replace references to 'testdisk' with 'hunter'...")
                with open(log_file, 'r') as log:
                    content = log.read()

                updated_content = content.replace("testdisk", "hunter")

                with open(log_file, 'w') as log:
                    log.write(updated_content)
                print(Fore.GREEN + "References in the log file updated successfully.")

            # Parse the log file to find deleted files
            if os.path.exists(log_file):
                print(Fore.GREEN + "Parsing Hunter log to identify deleted files...")
                with open(log_file, 'r') as log:
                    for line in log:
                        if "Deleted" in line:  # Adjust based on actual Hunter output
                            print(Fore.RED + f"Deleted file identified: {line.strip()}")
            else:
                print(Fore.YELLOW + "Log file not found. Unable to highlight deleted files.")

            print(Fore.GREEN + f"{self.hunter_tool} completed successfully! All recovered files are saved in: {self.recovery_directory}")

            # Explicitly print the recovery path as a message
            print(Fore.CYAN + f"Recovered files are available at: {self.recovery_directory}")

        except FileNotFoundError:
            print(Fore.RED + f"{self.hunter_tool} executable not found. Ensure it is correctly installed and accessible.")
        except subprocess.CalledProcessError as cpe:
            print(Fore.RED + f"{self.hunter_tool} encountered an error: {cpe}")
        except PermissionError:
            print(Fore.RED + f"Permission denied while accessing the recovery directory for {self.hunter_tool}.")
        except Exception as e:
            print(Fore.RED + f"An unexpected error occurred while running {self.hunter_tool}: {e}")



    def run_slayer(self):  # Enhanced for more comprehensive recovery
        print(f"Running {self.slayer_tool}...")

        try:
            # Use the same recovery directory as Hunter
            desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
            self.recovery_directory = os.path.join(desktop_dir, "Recovered_Files")
            
            # Ensure the recovery directory exists
            if not os.path.exists(self.recovery_directory):
                os.makedirs(self.recovery_directory)
                print(Fore.GREEN + f"Created recovery directory: {self.recovery_directory}")

            # Step 1: Run PhotoRec
            print(Fore.CYAN + "Starting PhotoRec for file recovery...")
            photorec_log_file = os.path.join(self.recovery_directory, "slayer_photorec.log")
            subprocess.run(
                ["sudo", "/usr/bin/photorec", "/log"], 
                cwd=self.recovery_directory, 
                check=True
            )

            # Rename and process PhotoRec log file
            original_photorec_log = os.path.join(self.recovery_directory, "photorec.log")
            if os.path.exists(original_photorec_log):
                os.rename(original_photorec_log, photorec_log_file)
                print(Fore.GREEN + "PhotoRec log file renamed to slayer_photorec.log.")

            # Process log file to update references
            if os.path.exists(photorec_log_file):
                print(Fore.GREEN + "Processing PhotoRec log file to replace references to 'photorec' with 'slayer'...")
                with open(photorec_log_file, 'r') as log:
                    content = log.read()

                updated_content = content.replace("photorec", "slayer")

                with open(photorec_log_file, 'w') as log:
                    log.write(updated_content)
                print(Fore.GREEN + "References in the log file updated successfully.")

            # Parse the log file to identify deleted files
            if os.path.exists(photorec_log_file):
                print(Fore.GREEN + "Parsing Slayer log to identify deleted files...")
                with open(photorec_log_file, 'r') as log:
                    for line in log:
                        if "Deleted" in line:  # Adjust based on actual log output
                            print(Fore.RED + f"Deleted file identified: {line.strip()}")
            else:
                print(Fore.YELLOW + "Log file not found. Unable to highlight deleted files.")

            print(Fore.GREEN + f"{self.slayer_tool} completed successfully with PhotoRec!")

            # Step 2: Add raw disk scanning (e.g., with foremost)
            print(Fore.CYAN + "Initiating raw disk scan for permanently deleted files...")
            raw_disk_tool = "/usr/bin/foremost"  # Example alternative tool for raw scans
            foremost_log_file = os.path.join(self.recovery_directory, "slayer_foremost.log")
            if os.path.exists(raw_disk_tool):
                subprocess.run(
                    [raw_disk_tool, "-t", "all", "-o", self.recovery_directory, "/dev/sdX"],
                    check=True
                )
                print(Fore.GREEN + "Raw disk scan completed successfully!")

                # Check for output log and rename for consistency
                if os.path.exists(os.path.join(self.recovery_directory, "foremost.log")):
                    os.rename(
                        os.path.join(self.recovery_directory, "foremost.log"), 
                        foremost_log_file
                    )
                    print(Fore.GREEN + "Foremost log file renamed to slayer_foremost.log.")
            else:
                print(Fore.YELLOW + "Raw disk scanning tool not found. Skipping this step.")

            # Explicit recovery path message
            print(Fore.CYAN + f"Recovered files are available at: {self.recovery_directory}")

        except FileNotFoundError:
            print(Fore.RED + f"{self.slayer_tool} or raw scanning tool not found. "
                            "Please ensure they are correctly installed.")
        except subprocess.CalledProcessError as cpe:
            print(Fore.RED + f"{self.slayer_tool} or raw scanning tool encountered an error: {cpe}")
        except PermissionError:
            print(Fore.RED + "Permission denied while accessing the recovery directory or disk. "
                            "Ensure you have the required permissions.")
        except Exception as e:
            print(Fore.RED + f"An unexpected error occurred while running {self.slayer_tool}: {e}")


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
        update                            - Update the FRECE tool to the latest version.
        hunter                            - Run hunter for data recovery, recovered files will be saved on the Desktop.
        slayer                            - Run slayer for data recovery, recovered files will be saved on the Desktop.
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
        - hunter
        - slayer
        - update
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
            'update': "Update the FRECE tool to the latest version",
            'hunter': "Run hunter to recover partitions and files.\nUsage: hunter",
            'slayer': "Run slayer to recover lost files by file signatures.\nUsage: slayer",
            'save': "Save recovered files to the specified directory.\nUsage: save <directory>",
            '--version': "Display the version of this tool.\nUsage: --version",
            '--help': "Display help for commands.\nUsage: --help",
            'frece': ("FRECE (File Recovery Console Enhanced) is a powerful tool designed for recovering files, "
                    "scanning directories for lost data, and providing data recovery options through utilities like hunter and slayer.\n"
                    "\nFeatures:\n"
                    "  - Recover files from source to target directory\n"
                    "  - Scan directories for files, optionally filtering by extension\n"
                    "  - List file types and counts in directories\n"
                    "  - Recover lost partitions and files with hunter\n"
                    "  - Recover files using file signatures with slayer\n"
                    "  - Save recovered files to a user-specified directory\n"
                    "  - Tab autocomplete for file paths, directories, and commands\n"
                    "  - Display tool version and help information\n"
                    "\nUsage examples:\n"
                    "  - recover /path/to/source /path/to/target\n"
                    "  - scan /path/to/directory .txt\n"
                    "  - list /path/to/directory\n"
                    "  - hunter\n"
                    "  - slayer\n"
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
                    if len(command_parts) == 3:  # source_dir and target_dir
                        _, source, target = command_parts

                        # Validate source and target directories
                        source = os.path.expanduser(source)
                        target = os.path.expanduser(target)

                        if not os.path.exists(source):
                            print(Fore.RED + f"Source directory {source} does not exist.")
                        else:
                            # Create target directory if not exists
                            if not os.path.exists(target):
                                print(Fore.RED + f"Target directory {target} does not exist. Creating it now.")
                                os.makedirs(target, exist_ok=True)
                                print(Fore.GREEN + f"Created target directory: {target}")

                            print(Fore.GREEN + f"Recovering all files and directories from {source} to {target}...")
                            self.recover_files(source, target)  # Recover both files and directories

                    elif len(command_parts) == 4:  # source_dir, extension, and target_dir
                        _, source, extension, target = command_parts

                        # Validate source and target directories
                        source = os.path.expanduser(source)
                        target = os.path.expanduser(target)

                        if not os.path.exists(source):
                            print(Fore.RED + f"Source directory {source} does not exist.")
                        else:
                            # Create target directory if not exists
                            if not os.path.exists(target):
                                print(Fore.RED + f"Target directory {target} does not exist. Creating it now.")
                                os.makedirs(target, exist_ok=True)
                                print(Fore.GREEN + f"Created target directory: {target}")

                            print(Fore.GREEN + f"Recovering files with extension {extension} from {source} to {target}...")
                            self.recover_files(source, target, extension)  # Recover files with the specified extension

                    elif len(command_parts) == 2:  # source_dir and extension ('null' or a file name)
                        _, source, extension = command_parts

                        # Validate source directory
                        source = os.path.expanduser(source)
                        if not os.path.exists(source):
                            print(Fore.RED + f"Source directory {source} does not exist.")
                        else:
                            # Check if extension is 'null' or specific filename
                            if extension == 'null':
                                print(Fore.GREEN + f"Recovering all files and directories from {source}...")
                                self.recover_files(source, target_dir=None, extension='null')  # Recover all files and directories
                            else:
                                print(Fore.GREEN + f"Recovering files or directories with name {extension} from {source}...")
                                self.recover_files(source, target_dir=None, extension=extension)  # Recover specific files/folders

                    else:
                        print(Fore.RED + "Invalid number of arguments. Usage: recover <source_dir> [extension] <target_dir>")

                elif command.startswith("save"):
                    parts = command.split(maxsplit=1)
                    if len(parts) == 2:
                        directory = parts[1]
                        self.save_recovery(directory)  # Save the recovered files to the specified directory
                    else:
                        print(Fore.RED + "Usage: save <directory>")
        

                elif command.startswith("scan"):
                    parts = command.split(maxsplit=2)  # Split the command into parts
                    if len(parts) >= 2:
                        directory = parts[1]  # The directory to scan
                        ext = parts[2] if len(parts) == 3 else None  # Optional extension
                        
                        # Call the scan_directory method with directory and extension
                        files = self.scan_directory(directory, ext)
                        if files:  # Check if files were successfully retrieved
                            print(Fore.GREEN + f"Found {len(files)} files in '{directory}'.")
                            if ext:
                                print(Fore.GREEN + f"Files filtered by extension: {ext}")
                    else:
                        print(Fore.RED + "Usage: scan <directory> [extension]")


                elif command.startswith("update"):
                    self.update_tool()  # Calls the update method

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


                elif command == 'hunter':  # Command for TestDisk
                    try:
                        # Define the recovery directory
                        recovery_directory = os.path.abspath(
                            os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_Files")
                        )

                        # Ensure the recovery directory exists
                        if not os.path.exists(recovery_directory):
                            os.makedirs(recovery_directory)
                            print(Fore.GREEN + f"Created recovery directory: {recovery_directory}")
                        else:
                            print(Fore.YELLOW + f"Using existing recovery directory: {recovery_directory}")

                        # Debugging information
                        print(f"Debug: Running Hunter with recovery directory: {recovery_directory}")

                        # Run Hunter with sudo (TestDisk)
                        testdisk_path = "/usr/bin/testdisk"  # Path to TestDisk

                        # Verify if TestDisk exists and is executable
                        if not os.path.isfile(testdisk_path) or not os.access(testdisk_path, os.X_OK):
                            raise FileNotFoundError("Hunter executable not found or is not executable.")

                        subprocess.run(["sudo", testdisk_path, "/log"], cwd=recovery_directory, check=True)
                        print(Fore.GREEN + "Hunter completed successfully!")

                    except FileNotFoundError:
                        print(Fore.RED + "Hunter executable not found. Ensure it is correctly installed and accessible.")
                    except subprocess.CalledProcessError as cpe:
                        print(Fore.RED + f"Hunter encountered an error: {cpe}")
                    except PermissionError:
                        print(Fore.RED + "Permission denied while accessing the recovery directory.")
                    except Exception as e:
                        print(Fore.RED + f"An unexpected error occurred: {e}")

                elif command == 'slayer':  # Command for PhotoRec
                    try:
                        # Define the recovery directory
                        recovery_directory = os.path.abspath(
                            os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_Files")
                        )

                        # Ensure the recovery directory exists
                        if not os.path.exists(recovery_directory):
                            os.makedirs(recovery_directory)
                            print(Fore.GREEN + f"Created recovery directory: {recovery_directory}")
                        else:
                            print(Fore.YELLOW + f"Using existing recovery directory: {recovery_directory}")

                        # Run Slayer (PhotoRec)
                        print(Fore.CYAN + "Launching Slayer ...")
                        photorec_path = "/usr/bin/photorec"  # Path to PhotoRec

                        # Verify if PhotoRec exists and is executable
                        if not os.path.isfile(photorec_path) or not os.access(photorec_path, os.X_OK):
                            raise FileNotFoundError("Slayer executable not found or is not executable.")

                        # Execute PhotoRec with the recovery directory as the output directory
                        subprocess.run(["sudo", photorec_path, "/log"], cwd=recovery_directory, check=True)
                        print(Fore.GREEN + "Slayer completed successfully!")

                    except FileNotFoundError as e:
                        print(Fore.RED + f"Slayer not found: {e}. Please ensure it is correctly installed.")
                    except subprocess.CalledProcessError as cpe:
                        print(Fore.RED + f"Slayer encountered an error while executing: {cpe}")
                    except PermissionError:
                        print(Fore.RED + "Permission denied while accessing the recovery directory. Ensure you have the required permissions.")
                    except Exception as e:
                        print(Fore.RED + f"An unexpected error occurred while running Slayer: {e}")




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

                    # Handle 'recover' command
                    elif command == 'recover':
                        if len(args) < 3:
                            print(Fore.RED + "Usage: recover <source_dir> <target_dir> [extension]")
                        else:
                            source = args[1]
                            target = args[2]
                            extension = args[3] if len(args) > 3 else None

                            # Expand source and target paths (support shortened paths)
                            source = os.path.expanduser(source)
                            target = os.path.expanduser(target)

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
                                if extension == 'null' or extension is None:
                                    print(Fore.GREEN + f"Recovering all files and directories from {source} to {target}...")
                                else:
                                    print(Fore.GREEN + f"Recovering files with extension '{extension}' from {source} to {target}...")

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
                    
                    # Handle 'save' command
                    elif command == 'save':
                        if len(args) < 2:
                            print(Fore.RED + "Usage: save <directory>")
                        else:
                            directory = args[1]

                            # Expand the directory path (support shortened paths)
                            directory = os.path.expanduser(directory)

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

                    elif command == 'scan':
                        if len(args) < 1:
                            print(Fore.RED + "Usage: scan <directory> [extension]")
                        else:
                            directory = args[0]  # Get the target directory from arguments
                            extension = args[1] if len(args) > 1 else None  # Optional extension if provided

                            # Call the scan_directory method
                            files = self.scan_directory(directory, extension)

                            # Check if files was retrieved correctly
                            if files is not None:
                                print(Fore.GREEN + f"Found {len(files)} files in '{directory}'.")
                                if extension:
                                    print(Fore.GREEN + f"Filtered by extension: {extension}")
                            else:
                                print(Fore.RED + "No files found or an error occurred during scanning.")



                        """Main entry point for the tool."""
                    elif '--update' in args:
                        self.update_tool()
                        return
                        
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

                    elif command == 'hunter':  # Command for TestDisk
                        try:
                            # Define the recovery directory path
                            recovery_directory = os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_Files")

                            # Ensure the recovery directory exists
                            if not os.path.exists(recovery_directory):
                                os.makedirs(recovery_directory)
                                print(Fore.GREEN + f"Created recovery directory: {recovery_directory}")
                            else:
                                print(Fore.YELLOW + f"Using existing recovery directory: {recovery_directory}")

                            # Debugging info
                            print(f"Debug: Checking Hunter executable and privileges...")

                            # Validate the Hunter executable
                            hunter_path = "/usr/bin/testdisk"
                            if not os.path.isfile(hunter_path) or not os.access(hunter_path, os.X_OK):
                                raise FileNotFoundError("Hunter executable not found or is not executable.")

                            # Check if the script has root privileges
                            if os.geteuid() != 0:
                                print(Fore.RED + "Hunter requires root privileges to run. Please re-run the script with 'sudo'.")
                                return

                            # Run the Hunter process with sudo
                            print(Fore.CYAN + "Launching Hunter with elevated privileges...")
                            subprocess.run(["sudo", hunter_path, "/log"], cwd=recovery_directory, check=True)
                            print(Fore.GREEN + "Hunter completed successfully!")

                            # Display recovery path
                            print(Fore.CYAN + f"Recovered files are saved in: {recovery_directory}")

                        except FileNotFoundError:
                            print(Fore.RED + "Hunter executable not found. Please ensure it is installed and accessible. "
                                            "You can install it using: 'sudo apt install testdisk'")
                        except subprocess.CalledProcessError as cpe:
                            print(Fore.RED + f"Hunter encountered an error while executing: {cpe}")
                        except PermissionError:
                            print(Fore.RED + "Permission denied while accessing the recovery directory. "
                                            "Ensure you have the required permissions.")
                        except Exception as e:
                            print(Fore.RED + f"An unexpected error occurred while running Hunter (TestDisk): {e}")

                    elif command == 'slayer':  # Command for PhotoRec
                        try:
                            # Define the recovery directory path
                            recovery_directory = os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_Files")

                            # Ensure the recovery directory exists
                            if not os.path.exists(recovery_directory):
                                os.makedirs(recovery_directory)
                                print(Fore.GREEN + f"Created recovery directory: {recovery_directory}")
                            else:
                                print(Fore.YELLOW + f"Using existing recovery directory: {recovery_directory}")

                            # Debugging info
                            print(Fore.CYAN + "Launching Slayer...")

                            # Validate the Slayer executable
                            slayer_path = "/usr/bin/photorec"
                            if not os.path.isfile(slayer_path) or not os.access(slayer_path, os.X_OK):
                                raise FileNotFoundError("Slayer executable not found or is not executable.")

                            # Run the Slayer process
                            subprocess.run([slayer_path, "/log"], cwd=recovery_directory, check=True)
                            print(Fore.GREEN + "Slayer completed successfully!")

                            # Display recovery path
                            print(Fore.CYAN + f"Recovered files are saved in: {recovery_directory}")

                        except FileNotFoundError:
                            print(Fore.RED + "Slayer executable not found. Please ensure it is installed and accessible. "
                                            "You can install it using: 'sudo apt install photorec'")
                        except subprocess.CalledProcessError as cpe:
                            print(Fore.RED + f"Slayer encountered an error while executing: {cpe}")
                        except PermissionError:
                            print(Fore.RED + "Permission denied while accessing the recovery directory. "
                                            "Ensure you have the required permissions.")
                        except Exception as e:
                            print(Fore.RED + f"An unexpected error occurred while running Slayer: {e}")




                    else:
                        print(Fore.RED + "Invalid command. Type '--help' for usage.")
                        return

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
    frece_tool = FRECE()
    frece_tool.start()
    frece_tool.update_tool()  # Call update_tool to test functionality

