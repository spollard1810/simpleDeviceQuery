#!/bin/bash

# Make script executable
chmod +x run.sh

echo "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed"
    echo "Please install Python 3.x using your package manager"
    exit 1
fi

echo "Checking/Installing requirements..."
python3 -m pip install -r requirements.txt

echo "Starting Device Query Maker..."
python3 main.py 