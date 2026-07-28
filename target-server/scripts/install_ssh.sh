#!/bin/bash

set -e

echo "[1/3] Installing OpenSSH server..."
sudo dnf install -y openssh-server

echo "[2/3] Enabling sshd..."
sudo systemctl enable --now sshd

echo "[3/3] Opening firewall SSH service..."
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload

echo "[OK] SSH installed and started."
echo "SSH log: /var/log/secure"
