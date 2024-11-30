#!/bin/bash

# Variables
REPO_URL="https://github.com/Nakum-hub/frece.git"
INSTALL_DIR="/usr/local/bin"  # Default installation directory
TOOL_NAME="frece"
SCRIPT_NAME="frece.py"
VENV_DIR="$HOME/frece_venv"  # Virtual environment location
FRECE_DIR="$INSTALL_DIR/frece"  # Directory for future installations inside /usr/local/bin

# Function to create directories
create_directories() {
    # Create the installation directory if it doesn't exist
    if [ ! -d "$INSTALL_DIR" ]; then
        echo "Creating installation directory at $INSTALL_DIR..."
        sudo mkdir -p "$INSTALL_DIR" || {
            echo "Failed to create installation directory. Exiting."
            exit 1
        }
    }

    # Create the frece directory for future tool updates if it doesn't exist
    if [ ! -d "$FRECE_DIR" ]; then
        echo "Creating $FRECE_DIR directory for future installations..."
        sudo mkdir -p "$FRECE_DIR" || {
            echo "Failed to create frece directory. Exiting."
            exit 1
        }
    }

    # Create the tool's repository directory inside the frece directory if it doesn't exist
    REPO_DIR="$FRECE_DIR/$TOOL_NAME-repo"
    if [ ! -d "$REPO_DIR" ]; then
        echo "Creating tool repository directory at $REPO_DIR..."
        sudo mkdir -p "$REPO_DIR" || {
            echo "Failed to create repository directory. Exiting."
            exit 1
        }
    }
}

# Install or update functionality
if [ "$1" == "--update" ]; then
    create_directories  # Ensure the directories are created if updating

    # Update functionality
    if [ -d "$REPO_DIR" ]; then
        echo "Updating the tool..."
        cd "$REPO_DIR"
        sudo git pull || {
            echo "Failed to pull updates. Please check your network connection."
            exit 1
        }
        sudo cp "$REPO_DIR/$SCRIPT_NAME" "$INSTALL_DIR/$TOOL_NAME"
        sudo chmod +x "$INSTALL_DIR/$TOOL_NAME"
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
echo "Cloning the repository directly into $REPO_DIR..."
git clone "$REPO_URL" "$REPO_DIR"

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

# Remove the cloned repository directory (clean-up)
rm -rf "$REPO_DIR"

# Display the success message
echo "Installation successful! To run '$TOOL_NAME', activate the virtual environment:"
echo "source $VENV_DIR/bin/activate && $TOOL_NAME --help"
