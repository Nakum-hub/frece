#!/bin/bash

# Variables
REPO_URL="https://github.com/Nakum-hub/frece.git"
INSTALL_DIR="/usr/local/bin"
TOOL_NAME="frece"
SCRIPT_NAME="frece.py"

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

# Install required Python dependencies
echo "Installing Python dependencies..."
pip3 install colorama pyreadline || {
    echo "Failed to install Python dependencies. Please check your Python environment."
    exit 1
}

# Install required tools (testdisk, photorec)
echo "Installing required recovery tools..."
if ! command -v testdisk &> /dev/null || ! command -v photorec &> /dev/null; then
    if [ "$(uname)" == "Linux" ]; then
        sudo apt update && sudo apt install -y testdisk || {
            echo "Failed to install testdisk and photorec. Please install them manually."
            exit 1
        }
    else
        echo "Unsupported OS. Please install testdisk and photorec manually."
        exit 1
    fi
fi

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

# Verify the installation
echo "Verifying installation..."
if ! $INSTALL_DIR/$TOOL_NAME --version &> /dev/null; then
    echo "Installation failed during verification. Please check the setup."
    exit 1
fi

# Display the success message
echo "Installation successful! You can now run '$TOOL_NAME' from anywhere."
