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
echo "Installation successful! You can now run '$TOOL_NAME' from anywhere."
