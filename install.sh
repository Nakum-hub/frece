#!/bin/bash

# Function to check if required directories exist and create them if necessary
create_required_directories() {
    if [ ! -d "$FRECE_DIR" ]; then
        echo "Creating the required directory: $FRECE_DIR..."
        mkdir -p "$FRECE_DIR" || {
            echo "Failed to create $FRECE_DIR. Exiting."
            exit 1
        }
    fi

    if [ ! -d "$REPO_DIR" ]; then
        echo "Creating the REPO_DIR directory: $REPO_DIR..."
        mkdir -p "$REPO_DIR" || {
            echo "Failed to create REPO_DIR directory. Exiting."
            exit 1
        }
    fi
}

# Function to install necessary dependencies
install_dependencies() {
    echo "Checking for necessary dependencies..."
    if ! command -v git &> /dev/null; then
        echo "Git is not installed. Installing Git..."
        sudo apt install -y git || {
            echo "Failed to install Git. Exiting."
            exit 1
        }
    fi

    if ! command -v python3 &> /dev/null; then
        echo "Python 3 is not installed. Installing Python 3..."
        sudo apt install -y python3 || {
            echo "Failed to install Python 3. Exiting."
            exit 1
        }
    fi

    # Add more dependency checks as needed
}



# Function to check and install Tab Completion dependencies
check_tab_dependencies() {
    echo "Checking for tab completion dependencies..."
    
    # Check for readline development package (might be necessary for Python readline)
    if ! dpkg -l | grep -q libreadline-dev; then
        echo "libreadline-dev is not installed. Installing..."
        sudo apt install -y libreadline-dev || {
            echo "Failed to install libreadline-dev. Exiting."
            exit 1
        }
    else
        echo "libreadline-dev is already installed."
    fi

    # Check if Python readline module is available
    if ! python3 -c "import readline" &> /dev/null; then
        echo "Python readline module is not installed. Installing..."
        pip install readline || {
            echo "Failed to install Python readline module. Exiting."
            exit 1
        }
    else
        echo "Python readline module is already installed."
    fi
}

# Call this function at the appropriate place in your install script
check_tab_dependencies  # Add this line in the main section before setup steps




# Function to check internet connectivity
check_internet() {
    # Try to ping a reliable external server
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        echo "No internet connection. Please check your network settings."
        exit 1
    fi
}


# Variables

REPO_URL="https://github.com/Nakum-hub/frece.git"

INSTALL_DIR="/usr/local/bin"  # Default installation directory

TOOL_NAME="frece"  # Main tool name for installation

SCRIPT_NAME="frece.py"  # Name of the Python script

VENV_DIR="$HOME/frece_venv"  # Virtual environment location

FRECE_DIR="/home/kali/frece"  # The directory where the install.sh script is

REPO_DIR="$FRECE_DIR/REPO_DIR/subfolder"  # Directory where the repository will be cloned (inside subfolder)

HUNTER_TOOL="hunter"  # New symbolic name for TestDisk
SLAYER_TOOL="slayer"  # New symbolic name for PhotoRec

# Function to create directories

create_directories() {
    # Ensure that the REPO_DIR exists
    if [ ! -d "$REPO_DIR" ]; then
        echo "Creating the REPO_DIR directory..."
        mkdir -p "$REPO_DIR" || {
            echo "Failed to create REPO_DIR directory. Exiting."
            exit 1
        }
    fi
}


# Install or update functionality


if [ "$1" == "--update" ]; then
    create_directories  # Ensure the directories are created if updating

    # Update functionality
    if [ -d "$REPO_DIR" ]; then
        echo "Updating the tool..."
        cd "$REPO_DIR"

        # Pull the latest changes from the repository
        git pull || {
            echo "Failed to pull updates. Please check your network connection."
            exit 1
        }

        echo "Tool updated successfully!"
    else
        echo "Tool not installed. Please install it first."
    fi

    exit 0
fi

# Check if the tool already exists in the installation directory

if [ -f "$INSTALL_DIR/$TOOL_NAME" ]; then
    echo "Tool already installed at $INSTALL_DIR/$TOOL_NAME"
    exit 1
fi

# Ensure git is installed

if ! command -v git &> /dev/null; then
    echo "Git is not installed. Please install git and rerun the script."
    exit 1
fi

# Ensure Python 3.x is installed

if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Please install Python 3 and rerun the script."
    exit 1
fi

# Additional update functionality for frece tool

if [ "$1" == "update" ] && [ "$2" == "$TOOL_NAME" ]; then
    if [ -d "$REPO_DIR" ]; then
        echo "Updating frece tool..."
        cd "$REPO_DIR"

# Attempt to stash changes if there are any
git stash save "Temporary stash before pulling updates"


        git pull || {
            echo "Failed to pull updates for frece. Please check your network connection."
            exit 1
        }

        cp "$REPO_DIR/$SCRIPT_NAME" "$INSTALL_DIR/$TOOL_NAME"
        chmod +x "$INSTALL_DIR/$TOOL_NAME"
        echo "frece tool updated successfully!"
    else
        echo "Installation directory not found. Please install the tool first."
    fi

    exit 0
fi

# Install required recovery tools (TestDisk, PhotoRec, and Foremost)

echo "Installing required recovery tools..."

# Function to check and install a specific tool
check_and_install_tool() {
    local tool_name=\$1
    if ! command -v "$tool_name" &> /dev/null; then
        echo "The tool '$tool_name' is not installed. Installing now..."
        sudo apt update && sudo apt install -y "$tool_name"
        if [ $? -eq 0 ]; then
            echo "The tool '$tool_name' was installed successfully."
        else
            echo "Failed to install the tool '$tool_name'. Please install it manually using: 'sudo apt install $tool_name'."
            exit 1
        fi
    else
        echo "The tool '$tool_name' is already installed."
    fi
}

# Check and install tools
if [ "$(uname)" == "Linux" ]; then
    check_and_install_tool "testdisk"  # For Hunter
    check_and_install_tool "photorec" # For Slayer
    check_and_install_tool "foremost" # Additional recovery tool for file carving
else
    echo "Unsupported OS. Please manually install testdisk, photorec, and foremost recovery tools."
    exit 1
fi

# Ensure the virtual environment uses the latest Python version

echo "Checking for the latest Python version..."

LATEST_PYTHON=$(command -v python3)

if [ -z "$LATEST_PYTHON" ]; then
    echo "Python 3 is not installed. Exiting."
    exit 1
fi

# Create or update the virtual environment to use the latest Python version

echo "Setting up the virtual environment with the latest Python..."

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating new virtual environment..."
    "$LATEST_PYTHON" -m venv "$VENV_DIR" || {
        echo "Failed to create virtual environment. Exiting."
        exit 1
    }
else
    echo "Updating the virtual environment with the latest Python..."
    rm -rf "$VENV_DIR"
    "$LATEST_PYTHON" -m venv "$VENV_DIR" || {
        echo "Failed to update virtual environment. Exiting."
        exit 1
    }
fi

# Activate the virtual environment and ensure pip is the latest version

echo "Activating the virtual environment and updating pip..."

source "$VENV_DIR/bin/activate"

pip install --upgrade pip setuptools wheel || {
    echo "Failed to upgrade pip and essential packages. Exiting."
    deactivate
    exit 1
}

echo "Python environment is set up and ready."

deactivate

# Create a Python virtual environment

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating a Python virtual environment..."
    python3 -m venv "$VENV_DIR" || {
        echo "Failed to create virtual environment. Exiting installation."
        exit 1
    }
fi

# Activate the virtual environment and install Python dependencies

echo "Activating the virtual environment and installing dependencies..."

source "$VENV_DIR/bin/activate"

pip install --upgrade pip || {
    echo "Failed to upgrade pip. Exiting installation."
    deactivate
    exit 1
}

pip install colorama || {
    echo "Failed to install Python dependencies (colorama). Exiting installation."
    deactivate
    exit 1
}

deactivate

# Create the REPO_DIR directory and clone the repository into it

create_directories  # Ensure the REPO_DIR directory exists

echo "Cloning the repository into $REPO_DIR..."

git clone "$REPO_URL" "$REPO_DIR" || {
    echo "Failed to clone repository. Exiting installation."
    exit 1
}

# Check if cloning was successful

if [ ! -d "$REPO_DIR" ]; then
    echo "Failed to clone repository. Exiting installation."
    exit 1
fi


# Function to check if readline library is installed
check_readline() {
    if ! python3 -c "import readline" &> /dev/null; then
        echo "Readline library not found! Please make sure it's installed for tab completion in the FRECE tool."
    fi
}

# Call the check_readline function
check_readline

# Move the main script to the installation directory

echo "Setting up the tool..."

mv "$REPO_DIR/$SCRIPT_NAME" "$INSTALL_DIR/$TOOL_NAME"

# Make the script executable

chmod +x "$INSTALL_DIR/$TOOL_NAME"

# Clean up by removing the cloned repository folder

rm -rf "$REPO_DIR"

# After completing the installation process...

echo "Installation successful!"
echo ""
echo "To run the '$TOOL_NAME', activate the virtual environment with the following command:"
echo "    source $VENV_DIR/bin/activate && $TOOL_NAME --help"
echo ""
echo "You can use '$HUNTER_TOOL' to recover partitions and files."
echo "You can use '$SLAYER_TOOL' to recover lost files by file signatures."
echo ""
echo "The FRECE tool now supports tab completion in interactive mode."
echo "You can use the 'scan' command to find files and directories."
echo ""
