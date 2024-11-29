#!/bin/bash

# Variables
REPO_URL="https://github.com/Nakum-hub/frece.git"
INSTALL_DIR="/usr/local/bin"
TOOL_NAME="frece"
SCRIPT_NAME="frece.py"
DEPENDENCIES=("git" "python3" "pip")

# Check if the tool already exists in the installation directory
if [ -f "$INSTALL_DIR/$TOOL_NAME" ]; then
    echo "Tool already installed at $INSTALL_DIR/$TOOL_NAME"
    exit 1
fi

# Verify dependencies
echo "Checking for required dependencies..."
for dep in "${DEPENDENCIES[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
        echo "Error: $dep is not installed. Please install it and rerun this script."
        exit 1
    fi
done

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

# Install Python dependencies
echo "Installing Python dependencies..."
pip install colorama pyreadline || {
    echo "Failed to install Python dependencies. Exiting installation."
    exit 1
}

# Remove the cloned repository directory (clean-up)
echo "Cleaning up..."
rm -rf "$INSTALL_DIR/$TOOL_NAME-repo"

# Verify installation
echo "Verifying installation..."
if "$TOOL_NAME" --version &>/dev/null; then
    echo "Installation successful! You can now run '$TOOL_NAME' from anywhere."
else
    echo "Installation failed during verification. Check your setup."
    exit 1
fi

# Optional: Add tool to PATH (if not already present)
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo "Adding $INSTALL_DIR to PATH in your shell configuration."
    echo "export PATH=\$PATH:$INSTALL_DIR" >>~/.bashrc
    source ~/.bashrc
    echo "PATH updated. You might need to restart your terminal."
fi
