#!/bin/bash

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

        git pull || {
            echo "Failed to pull updates. Please check your network connection."
            exit 1
        }

        cp "$REPO_DIR/$SCRIPT_NAME" "$INSTALL_DIR/$TOOL_NAME"
        chmod +x "$INSTALL_DIR/$TOOL_NAME"
        echo "Tool updated successfully!"
    else
        echo "Installation directory not found. Please install the tool first."
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

# Install required recovery tools (TestDisk and PhotoRec)

echo "Installing required recovery tools..."

if ! command -v testdisk &> /dev/null || ! command -v photorec &> /dev/null; then
    if [ "$(uname)" == "Linux" ]; then
        sudo apt update && sudo apt install -y testdisk photorec || {
            echo "Failed to install testdisk and photorec. Please install them manually."
            exit 1
        }
    else
        echo "Unsupported OS. Please install testdisk and photorec manually."
        exit 1
    fi
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

# Move the main script to the installation directory

echo "Setting up the tool..."

mv "$REPO_DIR/$SCRIPT_NAME" "$INSTALL_DIR/$TOOL_NAME"

# Make the script executable

chmod +x "$INSTALL_DIR/$TOOL_NAME"

# Clean up by removing the cloned repository folder

rm -rf "$REPO_DIR"

# Display the success message

echo "Installation successful! To run '$TOOL_NAME', activate the virtual environment:"
echo "source $VENV_DIR/bin/activate && $TOOL_NAME --help"

echo "You can use '$HUNTER_TOOL' to recover partitions and files."
echo "You can use '$SLAYER_TOOL' to recover lost files by file signatures."
