#!/bin/bash

# Variables
REPO_URL="https://github.com/Nakum-hub/frece.git"
INSTALL_DIR="/usr/local/bin"
TOOL_NAME="frece"
SCRIPT_NAME="frece.py"

# Check if the script already exists in the installation directory
if [ -f "$INSTALL_DIR/$TOOL_NAME" ]; then
    echo "Tool already installed at $INSTALL_DIR/$TOOL_NAME"
    exit 1
fi

# Clone the repository
echo "Cloning the repository..."
git clone "$REPO_URL" /tmp/frece

# Check if the cloning was successful
if [ ! -d "/tmp/frece" ]; then
    echo "Failed to clone repository. Exiting installation."
    exit 1
fi

# Create the symlink in the appropriate directory
echo "Creating symlink in $INSTALL_DIR..."
ln -sf /tmp/frece/$SCRIPT_NAME "$INSTALL_DIR/$TOOL_NAME"

# Make the script executable
chmod +x "$INSTALL_DIR/$TOOL_NAME"

# Clean up
rm -rf /tmp/frece

# Display the installation success message
echo "Installation successful! You can now run '$TOOL_NAME' from anywhere."
