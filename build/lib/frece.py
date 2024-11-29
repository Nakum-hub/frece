#!/usr/bin/env python3
import os
import sys
import random
from colorama import Fore, Style, init
import shutil
from pathlib import Path

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

# Display Dynamic Banner
def display_dynamic_banner():
    banners = [
        f"""{Fore.RED}
███████╗██████╗ ███████╗███████╗██████╗ ███████╗ ██████╗ 
██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔═══██╗
█████╗  ██║  ██║█████╗  █████╗  ██████╔╝█████╗  ██║   ██║
██╔══╝  ██║  ██║██╔══╝  ██╔══╝  ██╔═══╝ ██╔══╝  ██║   ██║
███████╗██████╔╝███████╗███████╗██║     ███████╗╚██████╔╝
╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝
{Fore.CYAN}File Recovery Tool
{Style.RESET_ALL}""",
        f"""{Fore.GREEN}
▀▀█▀▀ █▀▀ █▀▀▄ █▀▀█ █▀▀ █▀▀█ █▀▀▄ █▀▀▀ █▀▀ 
░▒█░░ █▀▀ █▀▀▄ █▄▄█ ▀▀█ █▄▄▀ █░░█ █░▀█ ▀▀█ 
░▒█░░ ▀▀▀ ▀▀▀░ ▀░░▀ ▀▀▀ ▀░▀▀ ▀▀▀░ ▀▀▀▀ ▀▀▀
{Fore.CYAN}File Recovery Console.
{Style.RESET_ALL}"""
    ]
    print(random.choice(banners))

class FRECE:
    def __init__(self):
        self.version = "FRECE v1.0"
    
    def scan_directory(self, target_dir, file_extension=None):
        """Scan the directory for files, optionally filtering by file extension."""
        found_files = []
        for root, dirs, files in os.walk(target_dir):
            for file in files:
                if file_extension and not file.endswith(file_extension):
                    continue
                file_path = os.path.join(root, file)
                found_files.append(file_path)
        return found_files

    def recover_files(self, found_files, recovery_dir=None):
        """Recover found files to the recovery directory."""
        if not recovery_dir:
            recovery_dir = "recovered_files"
        
        if not os.path.exists(recovery_dir):
            os.makedirs(recovery_dir)

        for file_path in found_files:
            try:
                base_name = os.path.basename(file_path)
                recovery_path = os.path.join(recovery_dir, base_name)

                # Check if the file is readable
                if not os.access(file_path, os.R_OK):
                    print(f"{Fore.RED}Permission denied: {file_path}{Style.RESET_ALL}")
                    continue

                with open(file_path, 'rb') as src_file:
                    with open(recovery_path, 'wb') as dst_file:
                        dst_file.write(src_file.read())
                print(f"{Fore.GREEN}Recovered: {file_path} -> {recovery_path}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error recovering {file_path}: {e}{Style.RESET_ALL}")

    def show_help(self):
        """Display the help message for the tool."""
        help_text = f"""
        {Fore.CYAN}FRECE - File Recovery Console{Style.RESET_ALL}
        A tool to recover and analyze deleted files from various file systems.

        {Fore.GREEN}Usage:{Style.RESET_ALL}
            FRECE> recover <target_dir> <recovery_dir>  - Recover files from the specified directory.
            FRECE> recover_recycle <recovery_dir>       - Recover files from the recycle bin.
            FRECE> search_deleted <target_dir>          - Search for deleted files.
            FRECE> hashcheck <recovery_dir>             - Verify the integrity of recovered files.
            FRECE> listpart <disk>                      - List all partitions on the specified disk.
            FRECE> image <disk> <image_path>            - Create a forensic-quality image of the disk.
            FRECE> carve <disk_image> <recovery_dir>    - Carve out files from a disk image.
            FRECE> report <recovery_dir>                - Generate a detailed recovery report.
            FRECE> view <file_path>                    - View the contents of a file.

        {Fore.YELLOW}Options:{Style.RESET_ALL}
            --version   Show the version of the tool.
            --help      Show help for a command.
            man <command>  Show detailed manual for a specific command (e.g., man recover).
            scan <dir> [<ext>]   Scan a directory for files, optionally filter by file extension.
        """
        print(help_text)

    def show_command_man(self, command):
        """Show the manual for a specific command."""
        manuals = {
            'recover': """
            recover <target_dir> <recovery_dir>
            - Recover files from the specified directory to the recovery directory.
            - If no recovery directory is provided, files are recovered to a default directory.
            """,
            'scan': """
            scan <dir> [<ext>]
            - Scan a directory for files, optionally filtering by file extension.
            - If no file extension is provided, all files are returned.
            """,
            'recover_recycle': """
            recover_recycle <recovery_dir>
            - Recover files from the recycle bin to the specified recovery directory.
            """,
            'search_deleted': """
            search_deleted <target_dir>
            - Search for deleted files within a specified directory.
            - Currently, this feature is not implemented.
            """,
            # You can add other commands here similarly.
        }
        manual = manuals.get(command, "Manual not found for this command.")
        print(f"{Fore.CYAN}Manual for '{command}':{Style.RESET_ALL}\n{manual}")

    def interactive_mode(self):
        """Run the tool in an interactive mode."""
        display_dynamic_banner()
        print(f"Welcome to {self.version}")
        print("Type '--help' for a list of available commands.")

        while True:
            try:
                command = input(f"{Fore.CYAN}FRECE> {Style.RESET_ALL}").strip()
                if command.startswith("recover"):
                    target_dir = command.split()[1]
                    recovery_dir = command.split()[2] if len(command.split()) > 2 else None
                    files = self.scan_directory(target_dir)
                    self.recover_files(files, recovery_dir)
                elif command.startswith("scan"):
                    parts = command.split()
                    target_dir = parts[1]
                    file_extension = parts[2] if len(parts) > 2 else None
                    files = self.scan_directory(target_dir, file_extension)
                    print(f"{Fore.CYAN}Found files:{Style.RESET_ALL}")
                    for file in files:
                        print(file)
                elif command.startswith("man"):
                    parts = command.split()
                    if len(parts) > 1:
                        self.show_command_man(parts[1])
                    else:
                        print(f"{Fore.RED}Error: Missing command name for 'man'.{Style.RESET_ALL}")
                elif command == "--version":
                    print(f"{Fore.CYAN}FRECE Version: {self.version}{Style.RESET_ALL}")
                elif command == "exit":
                    break
                elif command == "--help":
                    self.show_help()
                else:
                    print(f"{Fore.RED}Invalid command.{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print("\nExiting interactive mode.")
                break

    def start(self):
        """Start the tool, either interactive or command-line mode."""
        if '--version' in sys.argv:
            print(f"{Fore.CYAN}{self.version}{Style.RESET_ALL}")
            sys.exit(0)
        elif '--help' in sys.argv:
            self.show_help()
            sys.exit(0)

        if len(sys.argv) > 1:
            command = sys.argv[1]
            if command == "recover":
                if len(sys.argv) > 3:
                    target_dir = sys.argv[2]
                    recovery_dir = sys.argv[3]
                    files = self.scan_directory(target_dir)
                    self.recover_files(files, recovery_dir)
                else:
                    print(f"{Fore.RED}Error: Missing directories.{Style.RESET_ALL}")
            elif command == "scan":
                target_dir = sys.argv[2]
                file_extension = sys.argv[3] if len(sys.argv) > 3 else None
                files = self.scan_directory(target_dir, file_extension)
                for file in files:
                    print(file)
            else:
                print(f"{Fore.RED}Unknown command.{Style.RESET_ALL}")
        else:
            self.interactive_mode()

if __name__ == "__main__":
    frece = FRECE()
    frece.start()
