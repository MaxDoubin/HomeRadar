#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]] || ! command -v lb >/dev/null 2>&1; then
  echo "Build on Debian 12/13 with: sudo apt install live-build rsync"
  exit 1
fi

iso_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${iso_root}/.." && pwd)"
cd "${iso_root}"

mkdir -p config/package-lists config/includes.chroot/opt/homeradar
rsync -a --delete \
  --exclude .git --exclude .venv --exclude node_modules --exclude frontend/dist \
  --exclude backend/data --exclude iso/build --exclude iso/config \
  "${repo_root}/" config/includes.chroot/opt/homeradar/

for arch in amd64 i386; do
  lb clean
  lb config \
    --distribution bookworm \
    --architectures "${arch}" \
    --binary-images iso-hybrid \
    --debian-installer live \
    --archive-areas "main contrib non-free-firmware" \
    --bootappend-live "boot=live components quiet splash"

  lb build
  if [[ -f "live-image-${arch}.hybrid.iso" ]]; then
    mv "live-image-${arch}.hybrid.iso" "${iso_root}/live-image-${arch}.hybrid.iso.new"
  fi
done

for arch in amd64 i386; do
  if [[ -f "${iso_root}/live-image-${arch}.hybrid.iso.new" ]]; then
    mv "${iso_root}/live-image-${arch}.hybrid.iso.new" "${iso_root}/live-image-${arch}.hybrid.iso"
    echo "ISO created: ${iso_root}/live-image-${arch}.hybrid.iso"
  fi
done
