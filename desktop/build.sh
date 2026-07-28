#!/bin/bash

# Build the frontend
echo "Building frontend..."
cd ../frontend
npm install
npm run build
cd ../desktop

# Create resources directory
mkdir -p resources
mkdir -p resources/frontend
cp -r ../frontend/dist resources/frontend/

# Ensure virtual environment and install pyinstaller
echo "Packaging backend..."
cd ..
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
# Fix for cross-platform venv activation
if [ -f ".venv/Scripts/activate" ]; then
    source .venv/Scripts/activate
else
    source .venv/bin/activate
fi

pip install -r backend/requirements.txt
pip install pyinstaller

PYINSTALLER_CMD="pyinstaller"

# Determine OS and Pyinstaller flags
if [[ "$OSTYPE" == "darwin"* ]]; then
    # On macOS, --noconsole creates an .app bundle instead of a unix executable
    # Electron hides the stdout/stderr of spawned processes anyway, so we just use --onefile
    $PYINSTALLER_CMD --name homeradar-backend --onefile backend/main.py
else
    $PYINSTALLER_CMD --name homeradar-backend --onefile --noconsole backend/main.py
fi

if [ -f "dist/homeradar-backend.exe" ]; then
    mv dist/homeradar-backend.exe desktop/resources/
elif [ -f "dist/homeradar-backend" ]; then
    mv dist/homeradar-backend desktop/resources/
else
    echo "PyInstaller output not found!"
fi

cd desktop
echo "Done packaging resources."
