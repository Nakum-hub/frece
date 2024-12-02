#!/bin/bash

# Variables
REPO_URL="https://github.com/Nakum-hub/frece.git"
INSTALL_DIR="/usr/local/bin"
TOOL_NAME="frece"
SCRIPT_NAME="frece.py"
VENV_DIR="$HOME/frece_venv"
FRECE_DIR="/home/kali/frece"
REPO_DIR="$FRECE_DIR/REPO_DIR/subfolder"

# Function to detect Python dynamically
find_python() {
    for cmd in python3 python; do
        if command -v $cmd &>/dev/null; then
            echo "$cmd"
            return 0
        fi
    done
    echo ""
}

# Ensure Python is available
PYTHON_CMD=$(find_python)
if [ -z "$PYTHON_CMD" ]; then
    echo "No Python installation found. Attempting to install Python..."
    sudo apt update
    sudo apt install -y python3 python3-venv || {
        echo "Failed to install Python. Please manually install Python 3 and rerun the script."
        exit 1
    }
    PYTHON_CMD=$(find_python)
    if [ -z "$PYTHON_CMD" ]; then
        echo "Python installation failed. Exiting."
        exit 1
    fi
fi
echo "Using Python: $PYTHON_CMD"

# Function to check and install dependencies
install_dependencies() {
    echo "Ensuring Python dependencies are installed..."
    $PYTHON_CMD -m ensurepip || {
        echo "ensurepip failed. Trying to install pip manually..."
        sudo apt install -y python3-pip || {
            echo "Failed to install pip. Exiting."
            exit 1
        }
    }

    $PYTHON_CMD -m pip install --upgrade pip || {
        echo "Failed to upgrade pip. Exiting."
        exit 1
    }

    # Install python3-venv if not available
    if ! dpkg -l | grep -q python3-venv; then
        echo "Installing python3-venv..."
        sudo apt install -y python3-venv || {
            echo "Failed to install python3-venv. Exiting."
            exit 1
        }
    fi
}

# Call the function to install dependencies
install_dependencies

# Install required system packages
echo "Installing required recovery tools (testdisk, photorec)..."
if ! command -v testdisk &>/dev/null || ! command -v photorec &>/dev/null; then
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

# Create a Python virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating a Python virtual environment..."
    $PYTHON_CMD -m venv "$VENV_DIR" || {
        echo "Failed to create virtual environment. Exiting installation."
        exit 1
    }
fi

# Activate the virtual environment and install Python dependencies
echo "Activating the virtual environment and installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip || {
    echo "Failed to upgrade pip in virtual environment. Exiting installation."
    deactivate
    exit 1
}
pip install colorama || {
    echo "Failed to install Python dependencies in virtual environment. Exiting installation."
    deactivate
    exit 1
}
deactivate

# Create the REPO_DIR directory and clone the repository into it
if [ ! -d "$REPO_DIR" ]; then
    echo "Creating the REPO_DIR directory..."
    mkdir -p "$REPO_DIR"
fi

echo "Cloning the repository into $REPO_DIR..."
git clone "$REPO_URL" "$REPO_DIR" || {
    echo "Failed to clone repository. Exiting installation."
    exit 1
}

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
