#!/bin/bash

set -e

echo "[1/4] Installing vsftpd..."
sudo dnf install -y vsftpd

echo "[2/4] Enabling vsftpd..."
sudo systemctl enable --now vsftpd

echo "[3/4] Opening firewall FTP service..."
sudo firewall-cmd --permanent --add-service=ftp
sudo firewall-cmd --reload

echo "[4/4] Applying Mini SOC FTP logging config..."

sudo cp /etc/vsftpd/vsftpd.conf /etc/vsftpd/vsftpd.conf.bak.$(date +%Y%m%d%H%M%S)

sudo grep -q "Mini SOC FTP logging" /etc/vsftpd/vsftpd.conf || sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null <<'CONFIG'

# Mini SOC FTP logging
dual_log_enable=YES
log_ftp_protocol=YES
xferlog_file=/var/log/xferlog
vsftpd_log_file=/var/log/vsftpd.log
CONFIG

sudo touch /var/log/xferlog
sudo touch /var/log/vsftpd.log
sudo chmod 644 /var/log/xferlog /var/log/vsftpd.log

sudo systemctl restart vsftpd

echo "[OK] FTP installed and logging enabled."
echo "FTP log: /var/log/vsftpd.log"
echo "Transfer log: /var/log/xferlog"
