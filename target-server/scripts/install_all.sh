#!/bin/bash

set -e

cd "$(dirname "$0")/.."

bash scripts/install_ssh.sh
bash scripts/install_vsftpd.sh
bash scripts/install_auditd.sh
bash scripts/start_target.sh

echo "[OK] Target server setup completed."
