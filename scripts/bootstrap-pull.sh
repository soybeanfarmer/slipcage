#!/usr/bin/env bash
# One-time local bootstrap (Ubuntu 24.04). Inspect before running with sudo.
set -euo pipefail
[[ "${EUID}" -eq 0 ]] || { echo "Run with sudo" >&2; exit 1; }
[[ -f /etc/os-release ]] && . /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] || {
  echo "This bootstrap requires Ubuntu 24.04" >&2; exit 1;
}
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ansible git curl python3 ca-certificates openssh-client util-linux
install -d -m 0755 -o root -g root /etc/slipcage /var/lib/slipcage
cat > /etc/slipcage/localhost.ini <<'INV'
[research]
localhost ansible_connection=local ansible_python_interpreter=/usr/bin/python3
INV
chmod 0644 /etc/slipcage/localhost.ini
install -o root -g root -m 0755 "${REPO_ROOT}/scripts/pull-deploy.sh" \
  /usr/local/sbin/slipcage-pull-deploy
install -o root -g root -m 0644 "${REPO_ROOT}/systemd/slipcage-pull-deploy.service" \
  /etc/systemd/system/slipcage-pull-deploy.service
install -o root -g root -m 0644 "${REPO_ROOT}/systemd/slipcage-pull-deploy.timer" \
  /etc/systemd/system/slipcage-pull-deploy.timer
systemctl daemon-reload
systemctl enable --now slipcage-pull-deploy.timer
echo "Bootstrap complete. Publish a reviewed, CI-passing GitHub Release to deploy."
echo "Status: sudo systemctl status slipcage-pull-deploy.timer"
