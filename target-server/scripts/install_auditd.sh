#!/bin/bash

set -e

echo "[1/4] Installing auditd..."
sudo dnf install -y audit audit-libs audispd-plugins

echo "[2/4] Enabling auditd..."
sudo systemctl enable --now auditd

echo "[3/4] Applying Mini SOC audit rules..."
sudo tee /etc/audit/rules.d/mini-soc.rules > /dev/null <<'RULES'
# Mini SOC auditd rules

-w /etc/passwd -p wa -k identity_change
-w /etc/shadow -p wa -k identity_change
-w /etc/group -p wa -k identity_change
-w /etc/sudoers -p wa -k sudoers_change

-w /etc/ssh/sshd_config -p wa -k ssh_config_change
-w /etc/vsftpd/vsftpd.conf -p wa -k ftp_config_change

-w /home/soc/SOC-Project/target-server -p wa -k target_server_change
RULES

echo "[4/4] Loading audit rules..."
sudo augenrules --load

echo "[OK] auditd configured."
echo "Check rules: sudo auditctl -l"
echo "Check logs : sudo ausearch -k target_server_change -i"
