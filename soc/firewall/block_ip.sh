#!/bin/bash

ATTACKER_IP=$1

TARGET_IP=$2

PORT=$3

BACKUP_DIR="$HOME/soc/firewall/backup"

LOG_FILE="$HOME/soc/firewall/logs/firewall-action.log"

TIME=$(date +%Y%m%d-%H%M%S)

BACKUP_FILE="$BACKUP_DIR/iptables-$TIME.rules"

if [ -z "$ATTACKER_IP" ] || [ -z "$TARGET_IP" ]; then

echo "사용법: sudo ./block_ip.sh <공격자IP> <대상IP> [포트]"

exit 1

fi

mkdir -p "$BACKUP_DIR"

mkdir -p "$(dirname "$LOG_FILE")"

iptables-save > "$BACKUP_FILE"

if [ $? -ne 0 ]; then

echo "[ERROR] iptables 백업 실패"

echo "[$TIME] BACKUP_FAIL attacker=$ATTACKER_IP target=$TARGET_IP port=$PORT" >> "$LOG_FILE"

exit 1

fi

echo "[OK] 정책 백업 완료: $BACKUP_FILE"

if [ -z "$PORT" ]; then

iptables -I FORWARD -s "$ATTACKER_IP" -d "$TARGET_IP" -j DROP

ACTION="BLOCK_ALL"

else

iptables -I FORWARD -s "$ATTACKER_IP" -d "$TARGET_IP" -p tcp --dport "$PORT" -j DROP

ACTION="BLOCK_TCP_$PORT"

fi

if [ $? -eq 0 ]; then

echo "[OK] 차단 정책 적용 완료"

echo "[$TIME] $ACTION attacker=$ATTACKER_IP target=$TARGET_IP backup=$BACKUP_FILE" >> "$LOG_FILE"

else

echo "[ERROR] 차단 정책 적용 실패. 백업으로 복구합니다."

iptables-restore < "$BACKUP_FILE"

echo "[$TIME] APPLY_FAIL_RESTORE attacker=$ATTACKER_IP target=$TARGET_IP port=$PORT backup=$BACKUP_FILE" >> "$LOG_FILE"

exit 1

fi

iptables -L FORWARD -n -v --line-numbers
