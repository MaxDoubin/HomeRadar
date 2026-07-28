#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer with sudo."
  exit 1
fi

install_root=/opt/homeradar
config_root=/etc/homeradar
data_root=/var/lib/homeradar
service_user=homeradar
service_group=homeradar

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl iproute2 net-tools nodejs npm python3 python3-pip python3-venv rsync

if ! getent group "${service_group}" >/dev/null; then
  groupadd --system "${service_group}"
fi
if ! id -u "${service_user}" >/dev/null 2>&1; then
  useradd \
    --system \
    --gid "${service_group}" \
    --home-dir "${data_root}" \
    --shell /usr/sbin/nologin \
    "${service_user}"
fi

install -d -m 0755 -o root -g root "${install_root}" "${config_root}"
install -d -m 0750 -o "${service_user}" -g "${service_group}" "${data_root}"

rsync -a --delete \
  --exclude .git \
  --exclude .venv \
  --exclude node_modules \
  --exclude frontend/dist \
  --exclude backend/data \
  ./ "${install_root}/"

python3 -m venv "${install_root}/.venv"
"${install_root}/.venv/bin/python" -m pip install --upgrade pip
"${install_root}/.venv/bin/python" -m pip install -r "${install_root}/backend/requirements.txt"

npm --prefix "${install_root}/frontend" ci
npm --prefix "${install_root}/frontend" run build

chown -R root:root "${install_root}"
chmod -R go-w "${install_root}"

if [[ ! -f "${config_root}/homeradar.env" ]]; then
  install -m 0640 -o root -g "${service_group}" \
    "${install_root}/deploy/homeradar.env.example" \
    "${config_root}/homeradar.env"
else
  chown root:"${service_group}" "${config_root}/homeradar.env"
  chmod 0640 "${config_root}/homeradar.env"
fi

install -m 0644 "${install_root}/deploy/homeradar.service" /etc/systemd/system/
install -m 0644 "${install_root}/deploy/homeradar-blocklists.service" /etc/systemd/system/
install -m 0644 "${install_root}/deploy/homeradar-blocklists.timer" /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now homeradar.service homeradar-blocklists.timer

appliance_ip="$(hostname -I | awk '{print $1}')"
echo
echo "Home Radar is running at http://${appliance_ip:-127.0.0.1}:8000"
echo "Retrieve the temporary first-run code with:"
echo "  sudo journalctl -u homeradar --no-pager | grep 'PAIRING CODE'"
echo
echo "Do not change your router DNS setting until one test client works correctly."
echo "Configuration: ${config_root}/homeradar.env"
