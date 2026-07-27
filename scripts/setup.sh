#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer with sudo."
  exit 1
fi

install_root=/opt/homeradar
config_root=/etc/homeradar
data_root=/var/lib/homeradar

apt-get update
apt-get install -y python3 python3-venv nodejs npm iproute2 net-tools rsync
mkdir -p "${install_root}" "${config_root}" "${data_root}"
rsync -a --delete \
  --exclude .git --exclude .venv --exclude node_modules --exclude frontend/dist \
  --exclude backend/data \
  ./ "${install_root}/"
python3 -m venv "${install_root}/.venv"
"${install_root}/.venv/bin/python" -m pip install -r "${install_root}/backend/requirements.txt"
npm --prefix "${install_root}/frontend" install
npm --prefix "${install_root}/frontend" run build

if [[ ! -f "${config_root}/homeradar.env" ]]; then
  cp "${install_root}/deploy/homeradar.env.example" "${config_root}/homeradar.env"
  chmod 600 "${config_root}/homeradar.env"
fi

install -m 0644 "${install_root}/deploy/homeradar.service" /etc/systemd/system/
install -m 0644 "${install_root}/deploy/homeradar-blocklists.service" /etc/systemd/system/
install -m 0644 "${install_root}/deploy/homeradar-blocklists.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now homeradar.service homeradar-blocklists.timer

echo "Home Radar is running at http://$(hostname -I | awk '{print $1}'):8000"
echo "Set your router's DNS server to this machine after reviewing ${config_root}/homeradar.env."
