#!/bin/bash

ACTION=$1
ATTACKER_IP=$2
TARGET_IP=$3
PORT=$4

LOG_FILE="$HOME/soc/firewall/logs/firewall.log"
TIME=$(date +%Y%m%d-%H%M%S)

if [ -z "$ACTION" ] || [ -z "$ATTACKER_IP" ] || [ -z "$TARGET_IP" ]; then
  echo "사용법:"
  echo "sudo ./apply_policy.sh block <공격자IP> <대상IP> [포트]"
  echo "sudo ./apply_policy.sh unblock <공격자IP> <대상IP> [포트]"
  exit 1
fi

# 1. 정책 적용 전 백업
"$HOME/soc/firewall/backup_iptables.sh"

if [ $? -ne 0 ]; then
  echo "[ERROR] 백업 실패로 정책 적용 중단"
  exit 1
fi

# 2. AI 정책 적용
if [ "$ACTION" = "block" ]; then

  if [ -z "$PORT" ]; then
    iptables -I FORWARD -s "$ATTACKER_IP" -d "$TARGET_IP" -j DROP
    echo "[$TIME] BLOCK_ALL attacker=$ATTACKER_IP target=$TARGET_IP" >> "$LOG_FILE"
    echo "[OK] 전체 차단 적용"
  else
    iptables -I FORWARD -s "$ATTACKER_IP" -d "$TARGET_IP" -p tcp --dport "$PORT" -j DROP
    echo "[$TIME] BLOCK_TCP attacker=$ATTACKER_IP target=$TARGET_IP port=$PORT" >> "$LOG_FILE"
    echo "[OK] TCP/$PORT 차단 적용"
  fi

elif [ "$ACTION" = "unblock" ]; then

  if [ -z "$PORT" ]; then
    iptables -D FORWARD -s "$ATTACKER_IP" -d "$TARGET_IP" -j DROP
    echo "[$TIME] UNBLOCK_ALL attacker=$ATTACKER_IP target=$TARGET_IP" >> "$LOG_FILE"
    echo "[OK] 전체 차단 해제"
  else
    iptables -D FORWARD -s "$ATTACKER_IP" -d "$TARGET_IP" -p tcp --dport "$PORT" -j DROP
    echo "[$TIME] UNBLOCK_TCP attacker=$ATTACKER_IP target=$TARGET_IP port=$PORT" >> "$LOG_FILE"
    echo "[OK] TCP/$PORT 차단 해제"
  fi

else
  echo "[ERROR] ACTION은 block 또는 unblock만 가능"
  exit 1
fi

iptables -L FORWARD -n -v --line-numbers
