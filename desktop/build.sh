#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

echo "Building Home Radar dashboard..."
(
  cd frontend
  npm ci
  npm run build
)

rm -rf desktop/resources
mkdir -p desktop/resources/frontend
cp -R frontend/dist desktop/resources/frontend/dist

echo "Packaging Home Radar backend..."
python3 -m venv .venv
if [[ -f .venv/Scripts/python.exe ]]; then
  python_cmd=".venv/Scripts/python.exe"
else
  python_cmd=".venv/bin/python"
fi
"${python_cmd}" -m pip install --upgrade pip
"${python_cmd}" -m pip install -r backend/requirements.txt pyinstaller
"${python_cmd}" -m PyInstaller \
  --clean \
  --noconfirm \
  --name homeradar-backend \
  --onefile \
  backend/main.py

if [[ -f dist/homeradar-backend.exe ]]; then
  cp dist/homeradar-backend.exe desktop/resources/homeradar-backend.exe
elif [[ -f dist/homeradar-backend ]]; then
  cp dist/homeradar-backend desktop/resources/homeradar-backend
  chmod +x desktop/resources/homeradar-backend
else
  echo "PyInstaller did not produce the expected backend executable." >&2
  exit 1
fi

echo "Installing desktop dependencies..."
(
  cd desktop
  npm ci
  npm test
)

echo "Desktop resources are ready in desktop/resources/."
