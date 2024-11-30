#!/bin/bash

# Variables
REPO_URL="https://github.com/Nakum-hub/frece.git"
INSTALL_DIR="/usr/local/bin"
TOOL_NAME="frece"
SCRIPT_NAME="frece.py"
VENV_DIR="$HOME/frece_venv"  # Virtual environment location

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

# Install required system packages (testdisk, photorec)
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
    echo "Failed to install Python dependencies. Exiting installation."
    deactivate
    exit 1
}
deactivate

# Clone the repository directly into the installation directory
echo "Cloning the repository directly into $INSTALL_DIR..."
git clone "$REPO_URL" "$INSTALL_DIR/$TOOL_NAME-repo"

# Check if cloning was successful
if [ ! -d "$INSTALL_DIR/$TOOL_NAME-repo" ]; then
    echo "Failed to clone repository. Exiting installation."
    exit 1
fi

# Move the main script to the installation directory
echo "Setting up the tool..."
mv "$INSTALL_DIR/$TOOL_NAME-repo/$SCRIPT_NAME" "$INSTALL_DIR/$TOOL_NAME"

# Make the script executable
chmod +x "$INSTALL_DIR/$TOOL_NAME"

# Remove the cloned repository directory (clean-up)
rm -rf "$INSTALL_DIR/$TOOL_NAME-repo"



# Display the success message
echo "Installation successful! To run '$TOOL_NAME', activate the virtual environment:"
echo "source $VENV_DIR/bin/activate && $TOOL_NAME --help"
