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
   **** **  **                                                                               
  /**/ //  /**                                                                        **   **
 ****** ** /**  *****        ******  *****   *****   ******  **    **  *****  ****** //** ** 
///**/ /** /** **///**      //**//* **///** **///** **////**/**   /** **///**//**//*  //***  
  /**  /** /**/*******       /** / /*******/**  // /**   /**//** /** /******* /** /    /**   
  /**  /** /**/**////        /**   /**//// /**   **/**   /** //****  /**////  /**      **    
  /**  /** ***//******      /***   //******//***** //******   //**   //******/***     **     
  //   // ///  //////       ///     //////  /////   //////     //     ////// ///     //      
{Fore.CYAN}File Recovery Tool
{Style.RESET_ALL}""",
        
        f"""{Fore.GREEN}
ffffffffffffffff    iiii  lllllll                                                                                                                                                                                          
f::::::::::::::::f  i::::i l:::::l                                                                                                                                                                                          
f::::::::::::::::::f  iiii  l:::::l                                                                                                                                                                                          
f::::::fffffff:::::f        l:::::l                                                                                                                                                                                          
f:::::f       ffffffiiiiiii  l::::l     eeeeeeeeeeee         rrrrr   rrrrrrrrr       eeeeeeeeeeee        cccccccccccccccc   ooooooooooo vvvvvvv           vvvvvvv eeeeeeeeeeee    rrrrr   rrrrrrrrryyyyyyy           yyyyyyy
f:::::f             i:::::i  l::::l   ee::::::::::::ee       r::::rrr:::::::::r    ee::::::::::::ee    cc:::::::::::::::c oo:::::::::::oov:::::v         v:::::vee::::::::::::ee  r::::rrr:::::::::ry:::::y         y:::::y 
f:::::::ffffff        i::::i  l::::l  e::::::eeeee:::::ee     r:::::::::::::::::r  e::::::eeeee:::::ee c:::::::::::::::::co:::::::::::::::ov:::::v       v:::::ve::::::eeeee:::::eer:::::::::::::::::ry:::::y       y:::::y  
f::::::::::::f        i::::i  l::::l e::::::e     e:::::e     rr::::::rrrrr::::::re::::::e     e:::::ec:::::::cccccc:::::co:::::ooooo:::::o v:::::v     v:::::ve::::::e     e:::::err::::::rrrrr::::::ry:::::y     y:::::y   
f::::::::::::f        i::::i  l::::l e:::::::eeeee::::::e      r:::::r     r:::::re:::::::eeeee::::::ec::::::c     ccccccco::::o     o::::o  v:::::v   v:::::v e:::::::eeeee::::::e r:::::r     r:::::r y:::::y   y:::::y    
f:::::::ffffff        i::::i  l::::l e:::::::::::::::::e       r:::::r     rrrrrrre:::::::::::::::::e c:::::c             o::::o     o::::o   v:::::v v:::::v  e:::::::::::::::::e  r:::::r     rrrrrrr  y:::::y y:::::y     
f:::::f              i::::i  l::::l e::::::eeeeeeeeeee        r:::::r            e::::::eeeeeeeeeee  c:::::c             o::::o     o::::o    v:::::v:::::v   e::::::eeeeeeeeeee   r:::::r               y:::::y:::::y      
f:::::f              i::::i  l::::l e:::::::e                 r:::::r            e:::::::e           c::::::c     ccccccco::::o     o::::o     v:::::::::v    e:::::::e            r:::::r                y:::::::::y       
f:::::::f            i::::::il::::::le::::::::e                r:::::r            e::::::::e          c:::::::cccccc:::::co:::::ooooo:::::o      v:::::::v     e::::::::e           r:::::r                 y:::::::y        
f:::::::f            i::::::il::::::l e::::::::eeeeeeee        r:::::r             e::::::::eeeeeeee   c:::::::::::::::::co:::::::::::::::o       v:::::v       e::::::::eeeeeeee   r:::::r                  y:::::y         
f:::::::f            i::::::il::::::l  ee:::::::::::::e        r:::::r              ee:::::::::::::e    cc:::::::::::::::c oo:::::::::::oo         v:::v         ee:::::::::::::e   r:::::r                 y:::::y          
ffffffff            iiiiiiiillllllll    eeeeeeeeeeeeee        rrrrrrr                eeeeeeeeeeeeee      cccccccccccccccc   ooooooooooo            vvv            eeeeeeeeeeeeee   rrrrrrr                y:::::y           
                                                                                                                                                                                                           y:::::y            
                                                                                                                                                                                                          y:::::y             
                                                                                                                                                                                                         y:::::y              
                                                                                                                                                                                                        y:::::y               
                                                                                                                                                                                                       yyyyyyy                
{Fore.CYAN}File Recovery Tool
{Style.RESET_ALL}""",
        
        f"""{Fore.RED}
 ________ ___  ___       _______           ________  _______   ________  ________  ___      ___ _______   ________      ___    ___ 
|\  _____\\  \|\  \     |\  ___ \         |\   __  \|\  ___ \ |\   ____\|\   __  \|\  \    /  /|\  ___ \ |\   __  \    |\  \  /  /|
\ \  \__/\ \  \ \  \    \ \   __/|        \ \  \|\  \ \   __/|\ \  \___|\ \  \|\  \ \  \  /  / | \   __/|\ \  \|\  \   \ \  \/  / /
 \ \   __\\ \  \ \  \    \ \  \_|/__       \ \   _  _\ \  \_|/_\ \  \    \ \  \\\  \ \  \/  / / \ \  \_|/_\ \   _  _\   \ \    / / 
  \ \  \_| \ \  \ \  \____\ \  \_|\ \       \ \  \\  \\ \  \_|\ \ \  \____\ \  \\\  \ \    / /   \ \  \_|\ \ \  \\  \ \  \ \  / / 
   \ \__\   \ \__\ \_______\\ \_______\       \ \__\\ _\\ \_______\ \_______\ \_______\ \__/ /     \ \_______\ \__\\ _\\ \ \ \/ / / 
    \|__|    \|__|\|_______| \|_______|        \|__|\|__|\|_______|\|_______|\|_______|\|__|/       \|_______|\|__|\|__|\ \__/ /  
                                                                                                                         \|__/ /   
{Fore.CYAN}File Recovery Tool
{Style.RESET_ALL}"""
    ]
    print(random.choice(banners))  # Randomly select a banner

class FRECE:
    def __init__(self):
        self.version = "FRECE v1.0"

    def scan_directory(self, directory, extension=None):
        """Scans the directory and returns a list of files, optionally filtering by extension."""
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
        """Recovers files from source directory to the target directory."""
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
        """Displays help for available commands."""
        print(Fore.CYAN + """Available Commands:
    recover <source_dir> <target_dir> - Recover files from source to target.
    scan <directory> [extension]      - Scan directory for files, optionally filter by extension.
    man <command>                    - Show manual for a command.
    --version                        - Show the tool version.
    --help                           - Show this help.""" )

    def show_command_man(self, command):
        """Displays the manual for a specific command."""
        if command == 'recover':
            print(Fore.CYAN + """
Recover Command:
Usage: recover <source_dir> <target_dir>
Description: This command recovers files from the source directory to the target directory.
            """)
        elif command == 'scan':
            print(Fore.CYAN + """
Scan Command:
Usage: scan <directory> [extension]
Description: This command scans the specified directory and returns a list of files.
             Optionally, filter files by their extension.
            """)
        else:
            print(Fore.RED + "No manual found for this command.")

    def interactive_mode(self):
        """Interactive mode to handle user commands."""
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
        """Entry point for the tool."""
        if len(sys.argv) > 1:
            if sys.argv[1] == '--version':
                print(self.version)
            elif sys.argv[1] == '--help':
                self.show_help()
            elif sys.argv[1] == 'recover':
                source, target = sys.argv[2], sys.argv[3]
                self.recover_files(source, target)
            elif sys.argv[1] == 'scan':
                directory = sys.argv[2]
                extension = sys.argv[3] if len(sys.argv) > 3 else None
                files = self.scan_directory(directory, extension)
                print(f"Found {len(files)} files.")
            elif sys.argv[1] == 'man':
                self.show_command_man(sys.argv[2])
            else:
                print(Fore.RED + "Invalid command. Type '--help' for usage.")
        else:
            display_dynamic_banner()
            self.interactive_mode()

if __name__ == "__main__":
    tool = FRECE()
    tool.start()
