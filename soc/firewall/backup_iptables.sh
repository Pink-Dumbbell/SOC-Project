#!/bin/bash

BACKUP_DIR="$HOME/soc/firewall/backup"
LOG_FILE="$HOME/soc/firewall/logs/firewall.log"
TIME=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/iptables-$TIME.rules"

mkdir -p "$BACKUP_DIR"

iptables-save > "$BACKUP_FILE"

if [ $? -eq 0 ]; then
  echo "[OK] 백업 완료: $BACKUP_FILE"
  echo "[$TIME] BACKUP_SUCCESS file=$BACKUP_FILE" >> "$LOG_FILE"
  exit 0
else
  echo "[ERROR] 백업 실패"
  echo "[$TIME] BACKUP_FAIL" >> "$LOG_FILE"
  exit 1
fi
