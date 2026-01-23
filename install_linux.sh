#!/bin/bash

echo "BGP Monitor Installation Script for Linux"
echo "========================================="

# Check if conda is installed
if ! command -v conda &> /dev/null; then
    echo "ERROR: Conda is not installed or not in PATH."
    echo "Please install Miniconda or Anaconda first."
    echo "Download from: https://docs.conda.io/en/latest/miniconda.html"
    echo "Or install via: wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh"
    exit 1
fi

echo "Creating conda environment 'bgpmon' with Python 3.11..."
conda create -n bgpmon python=3.11 -y
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create conda environment."
    exit 1
fi

echo "Activating environment and installing requirements..."
source "$(conda info --base)/etc/profile.d/conda.sh"
conda activate bgpmon
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to activate conda environment."
    exit 1
fi

pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install requirements."
    exit 1
fi

echo ""
echo "Installation completed successfully!"
echo ""
echo "To use the BGP Monitor:"
echo "1. Run: conda activate bgpmon"
echo "2. Run: python main.py"
echo ""
echo "For Neo4j setup, refer to the README.md file."
echo ""

# Make the script executable (in case it wasn't)
chmod +x "$0"