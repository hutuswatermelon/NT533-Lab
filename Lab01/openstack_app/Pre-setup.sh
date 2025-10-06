#!/bin/bash
set -e
echo "Updating system packages"
sudo apt update && sudo apt upgrade -y

echo "Installing Python environment and base tools"
sudo apt install -y python3 python3-pip python3-venv git curl wget

echo "Installing OpenStack CLI (optional but recommended)"
sudo apt install -y python3-openstackclient

echo "Creating Python virtual environment"
python3 -m venv venv
source venv/bin/activate

echo "Installing Python dependencies from requirements.txt"
pip install --upgrade pip
pip install -r requirements.txt

echo "=== ✅ Setup complete! ==="
