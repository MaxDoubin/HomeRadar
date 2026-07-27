#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]] || ! command -v lb >/dev/null 2>&1; then
  echo "Build on Debian 12/13 with: sudo apt install live-build rsync"
  exit 1
fi

iso_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${iso_root}/.." && pwd)"
cd "${iso_root}"

lb clean
lb config \
  --distribution bookworm \
  --architectures amd64 \
  --binary-images iso-hybrid \
  --debian-installer live \
  --archive-areas "main contrib non-free-firmware" \
  --bootappend-live "boot=live components quiet splash"

mkdir -p config/package-lists config/includes.chroot/opt/homeradar
rsync -a --delete \
  --exclude .git --exclude .venv --exclude node_modules --exclude frontend/dist \
  --exclude backend/data --exclude iso/build --exclude iso/config \
  "${repo_root}/" config/includes.chroot/opt/homeradar/

lb build
echo "ISO created: ${iso_root}/live-image-amd64.hybrid.iso"
